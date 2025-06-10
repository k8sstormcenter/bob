ARG GO_VERSION=1.24

# Use the official Go image as the base
FROM cgr.dev/chainguard/go:${GO_VERSION}

# Set the working directory
WORKDIR /app

# Install any necessary packages (optional, add what you need)
# RUN apt-get update && apt-get install -y --no-install-recommends \
#   <your-packages-here> \
#   && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
# COPY . /app

# Expose any ports your application might use (optional)
# EXPOSE 8080

# Command to run when the container starts (optional)
# CMD ["go", "run", "main.go"]