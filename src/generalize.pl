#!/usr/bin/env perl
use strict;
use warnings;
use feature 'say';
use File::Spec;
use File::Basename;
use YAML::XS qw(LoadFile Dump);
use JSON::MaybeXS qw(encode_json decode_json);
use Getopt::Long;

# Usage: make_superset.pl <input_dir> <output_file>
my ($input_dir, $output_file);
GetOptions() or die "Bad options";
($input_dir, $output_file) = @ARGV;
die "Usage: $0 <input_dir> <output_file>\n" unless $input_dir && $output_file;
die "Directory not found: $input_dir\n" unless -d $input_dir;

opendir my $dh, $input_dir or die "opendir $input_dir: $!";
my @files = map { File::Spec->catfile($input_dir, $_) } grep { /\.ya?ml$/i } readdir $dh;
closedir $dh;
die "No YAML files found in $input_dir\n" unless @files;

# Accumulators
my %acc = (
  syscalls    => {},
  capabilities=> {},
  execs       => {},   # path => example object
  endpoints   => {},
  rules       => {},   # key => set of processAllowed entries (as set)
  opens_raw   => [],   # list of objects {flags=>[], path=>str}
  meta        => {},   # store last-seen metadata fields used for template
);

# Helpers
sub uniq_array {
  my @a = @_;
  my %seen;
  return grep { !$seen{$_}++ } @a;
}

sub normalize_path {
  my ($p) = @_;
  return "" unless defined $p and length $p;
  # Collapse long hex hashes (>=32 hex)
  $p =~ s/[0-9a-f]{32,}/⋯/gi;
  # Collapse pod UIDs
  $p =~ s/pod[0-9a-fA-F_\-]+/⋯/g;
  # containerd CRI ids
  $p =~ s/cri-containerd-[0-9a-f]{64}\.scope/⋯.scope/g;
  # timestamps like ..2025_06_19_..
  $p =~ s/\.\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\.[0-9]+/⋯/g;
  # numeric segments (but avoid turning /etc/hosts or /proc/1 into ⋯ if you prefer – we replace digits with ⋯)
  $p =~ s{/(?=\d)(\d+)}{/⋯}g;
  return $p;
}

sub ensure_open_obj {
  my ($o) = @_;
  # accept string or object
  if (!defined $o) { return { flags => [], path => "" }; }
  if (ref($o) eq '') {
    # string path
    return { flags => [], path => $o };
  } elsif (ref($o) eq 'HASH') {
    # ensure keys
    $o->{flags} = [] unless exists $o->{flags};
    $o->{path}  = "" unless exists $o->{path};
    return $o;
  } else {
    # unknown type, stringify
    return { flags => [], path => "$o" };
  }
}

# Read and merge each file
for my $file (@files) {
  my $data = eval { LoadFile($file) };
  if ($@) {
    warn "Failed to parse YAML $file: $@ -- skipping\n";
    next;
  }

  # store some meta fields (last-file wins)
  for my $k (qw(metadata spec)) {
    $acc{meta}{$k} = $data->{$k} if exists $data->{$k};
  }

  # containers [0] may be absent
  my $c = $data->{spec}{containers}[0] // {};
  # syscalls and capabilities
  if (ref($c->{syscalls}) eq 'ARRAY') {
    $acc{syscalls}{$_} = 1 for grep {defined $_} @{ $c->{syscalls} };
  }
  if (ref($c->{capabilities}) eq 'ARRAY') {
    $acc{capabilities}{$_} = 1 for grep {defined $_} @{ $c->{capabilities} };
  }
  # execs: array of objs with .path
  if (ref($c->{execs}) eq 'ARRAY') {
    for my $e (@{ $c->{execs} }) {
      next unless defined $e;
      my $path = ref($e) ? ($e->{path} // '') : $e;
      next unless length $path;
      $acc{execs}{$path} = $e;
    }
  }
  # endpoints
  if (ref($c->{endpoints}) eq 'ARRAY') {
    $acc{endpoints}{$_} = 1 for @{ $c->{endpoints} };
  }
  # rules -> rulePolicies map
  if (exists $c->{rulePolicies} && ref($c->{rulePolicies}) eq 'HASH') {
    for my $rk (keys %{ $c->{rulePolicies} }) {
      my $val = $c->{rulePolicies}{$rk}{processAllowed} // [];
      for my $p (@$val) { $acc{rules}{$rk}{$p} = 1 if defined $p; }
    }
  }

  # opens
  my $opens = $c->{opens};
  if (!defined $opens) {
    # nothing
  } elsif (ref($opens) eq '') {
    # string or multiline string containing paths (rare)
    my @lines = split /\R/, $opens;
    for my $ln (@lines) {
      push @{$acc{opens_raw}}, ensure_open_obj($ln);
    }
  } elsif (ref($opens) eq 'ARRAY') {
    for my $o (@$opens) {
      push @{$acc{opens_raw}}, ensure_open_obj($o);
    }
  } elsif (ref($opens) eq 'HASH') {
    # maybe map-like, turn into array
    for my $k (keys %$opens) {
      push @{$acc{opens_raw}}, ensure_open_obj({ flags => $opens->{$k}{flags} // [], path => $k });
    }
  } else {
    # unknown shape, skip
  }
}

# Normalize all opens: make sure flags are sorted, path normalized
for my $o (@{ $acc{opens_raw} }) {
  $o->{flags} = [ sort { $a cmp $b } map { $_ // '' } @{ $o->{flags} || [] } ];
  $o->{path}  = normalize_path($o->{path} // '');
  # convert bare '/some/path' strings that are empty to ignore
}

# Convert any bare-string-only opens into object with default O_RDONLY if no flags
$_->{flags} = ['O_RDONLY'] if (!$_->{flags} || !@{$_->{flags}}) for @{ $acc{opens_raw} };

# Flatten duplicates by identical path+flags
my %seen;
my @opens_clean;
for my $o (@{ $acc{opens_raw} }) {
  my $k = join("|", join(",", @{ $o->{flags} }), "|", $o->{path});
  next if $seen{$k}++;
  push @opens_clean, $o;
}
$acc{opens_raw} = \@opens_clean;

# Helper: split into components (no leading empty)
sub parts { my $p = shift; return [] unless defined $p and length $p; my @s = split m{/+}, $p; @s = grep { length } @s; return \@s; }

# Convert pattern (with *, **, ⋯) into path-component-aware regex
sub pattern_to_regex {
  my ($pat) = @_;
  return qr/^$/ unless defined $pat;
  # escape regex special except our tokens: * , ** , ⋯
  # We'll first replace occurrences of '**' to a placeholder, then process '*'
  my $tmp = $pat;
  $tmp =~ s{([.^\$+(){}\[\]\\|])}{\\$1}g; # escape regex special chars
  # Restore our tokens if escaped
  $tmp =~ s/\\\*\\\*/\{\{GLOBSTAR\}\}/g;   # ** placeholder
  $tmp =~ s/\\\*/\{\{SINGLESTAR\}\}/g;     # * placeholder
  $tmp =~ s/\\⋯/⋯/g;                       # if escaped
  # Now convert tokens to regex:
  # - '⋯' matches exactly one path component (no slash)
  $tmp =~ s/⋯/[^\/]+/g;
  # - single star '*' matches within a component (any chars except slash) -> [^/]* 
  $tmp =~ s/\{\{SINGLESTAR\}\}/[^\/]*/g;
  # - globstar '**' matches zero or more components -> (?:.*)
  $tmp =~ s/\{\{GLOBSTAR\}\}/(?:.*)/g;
  return qr/^$tmp$/;
}

# Group paths by parent directory (string)
sub parent_dir {
  my ($p) = @_;
  $p //= '';
  $p =~ s{/$}{}; # strip trailing
  my @c = parts($p);
  pop @c; # remove last component
  return join("/", @c);
}

# Collapse many files in same folder into globs (*.ext or *)
sub collapse_folder_globs {
  my ($opens) = @_;
  # group by parent dir
  my %by_parent;
  for my $o (@$opens) {
    push @{ $by_parent{ parent_dir($o->{path}) } }, $o;
  }
  my @out;
  for my $parent (keys %by_parent) {
    my $arr = $by_parent{$parent};
    # if more than threshold, collapse
    if (scalar(@$arr) > 3) {
      # determine extensions
      my %exts;
      for my $o (@$arr) {
        my ($name) = $o->{path} =~ m{([^/]+)$};
        my ($ext) = $name =~ m/\.([^.\/]+)$/;
        $exts{$ext} = 1 if defined $ext;
      }
      if (keys %exts == 1) {
        my ($only) = keys %exts;
        push @out, { flags => $arr->[0]{flags}, path => ($parent ? "$parent/" : "") . "*.$only" };
      } else {
        push @out, { flags => $arr->[0]{flags}, path => ($parent ? "$parent/" : "") . "*" };
      }
    } else {
      push @out, map { { flags => $_->{flags}, path => $_->{path} } } @$arr;
    }
  }
  return \@out;
}

# Collapse multi-file event dirs into /* when more than one file exists under that dir
sub collapse_event_dirs {
  my ($opens) = @_;
  my %by_parent;
  for my $o (@$opens) {
    push @{ $by_parent{ parent_dir($o->{path}) } }, $o;
  }
  my @out;
  for my $parent (keys %by_parent) {
    my $arr = $by_parent{$parent};
    if (scalar(@$arr) > 1) {
      push @out, { flags => $arr->[0]{flags}, path => ($parent ? "$parent/" : "") . "*" };
    } else {
      push @out, map { { flags => $_->{flags}, path => $_->{path} } } @$arr;
    }
  }
  return \@out;
}

# Flag-sensitive dedup: if an existing kept entry with same flags "contains" candidate path, skip candidate
sub dedup_flag_sensitive {
  my ($opens) = @_;
  my @items = map { { %$_ } } @$opens; # shallow copy
  # Sort by specificity: broader patterns first -> we want broader patterns tested first so they remove specifics
  # We'll define specificity score: fewer path components -> broader; patterns with '*' or '⋯' are broader.
  my %score;
  for my $it (@items) {
    my @p = parts($it->{path});
    my $base = scalar(@p);
    my $wild = ($it->{path} =~ /\*\*/ ? 2 : ($it->{path} =~ /\*/ ? 1 : 0));
    my $dots = ($it->{path} =~ /⋯/ ? 1 : 0);
    # broader should have smaller "base" or contain wildcards -> we compute sort key as (base - wild - dots)
    $score{$it->{path}} = $base - $wild - $dots;
  }
  @items = sort { $score{$a->{path}} <=> $score{$b->{path}} or length($a->{path}) <=> length($b->{path}) } @items;

  my @kept;
  ITEM:
  for my $it (@items) {
    # build regex of each kept item to test containment
    for my $k (@kept) {
      next unless join("|", @{ $k->{flags} }) eq join("|", @{ $it->{flags} }); # flags must match
      my $k_re = pattern_to_regex($k->{path});
      # test if candidate path MATCHES kept pattern (meaning kept covers candidate)
      if ($it->{path} =~ $k_re) {
        # candidate is covered by existing kept pattern -> skip
        next ITEM;
      }
    }
    # not covered by any kept -> keep it
    push @kept, $it;
  }
  return \@kept;
}

# Apply successive collapsing passes
my $opens = $acc{opens_raw};

# If any path is empty, drop
$opens = [ grep { length($_->{path}) } @$opens ];

# 1) Collapse many files in same folder
$opens = collapse_folder_globs($opens);

# 2) Collapse multi-file event directories (/*)
$opens = collapse_event_dirs($opens);

# 3) Normalize duplicated patterns (e.g. convert /dir/⋯/file to consistent form)
#    We also want to collapse things like /dir/⋯/something and /dir/* to a consistent broader item if flags match
#    Use dedup_flag_sensitive which tests pattern containment component-aware
$opens = dedup_flag_sensitive($opens);

# Final sort (for stable output)
@{$opens} = sort { $a->{path} cmp $b->{path} || join(",",@{$a->{flags}}) cmp join(",",@{$b->{flags}}) } @{$opens};

# Build final profile structure (minimal fields)
my %profile = (
  apiVersion => 'spdx.softwarecomposition.kubescape.io/v1beta1',
  kind => 'ApplicationProfile',
  metadata => {
    name => ($acc{meta}{metadata}{name} // 'superset-profile'),
    namespace => ($acc{meta}{metadata}{namespace} // 'default'),
    annotations => {
      'kubescape.io/completion' => 'complete',
      'kubescape.io/status'     => 'completed',
      'kubescape.io/instance-id'=> ($acc{meta}{metadata}{annotations}{'kubescape.io/instance-id'} // ''),
      'kubescape.io/wlid'       => ($acc{meta}{metadata}{annotations}{'kubescape.io/wlid'} // ''),
    },
    labels => {
      'kubescape.io/workload-api-group' => ($acc{meta}{metadata}{labels}{'kubescape.io/workload-api-group'} // ''),
      'kubescape.io/workload-api-version' => ($acc{meta}{metadata}{labels}{'kubescape.io/workload-api-version'} // ''),
      'kubescape.io/workload-kind' => ($acc{meta}{metadata}{labels}{'kubescape.io/workload-kind'} // ''),
      'kubescape.io/workload-name' => ($acc{meta}{metadata}{labels}{'kubescape.io/workload-name'} // ''),
      'kubescape.io/workload-namespace' => ($acc{meta}{metadata}{labels}{'kubescape.io/workload-namespace'} // ''),
    },
  },
  spec => {
    architectures => [ ($acc{meta}{spec}{architectures}[0] // '') ],
    containers => [
      {
        capabilities => [ sort keys %{ $acc{capabilities} } ],
        endpoints => [], # we merged endpoints but leaving empty for brevity
        execs => [ map { $acc{execs}{$_} } sort keys %{ $acc{execs} } ],
        identifiedCallStacks => ($acc{meta}{spec}{containers}[0]{identifiedCallStacks} // undef),
        imageID => ($acc{meta}{spec}{containers}[0]{imageID} // ''),
        imageTag => ($acc{meta}{spec}{containers}[0]{imageTag} // ''),
        name => ($acc{meta}{spec}{containers}[0]{name} // ''),
        opens => $opens,
        rulePolicies => {}, # collapsed rules omitted for brevity
        seccompProfile => { spec => { defaultAction => "" } },
        syscalls => [ sort keys %{ $acc{syscalls} } ],
      }
    ]
  }
);

# Dump YAML
open my $out, '>', $output_file or die "open $output_file: $!";
print $out Dump(\%profile);
close $out;
say "Wrote superset to $output_file";
