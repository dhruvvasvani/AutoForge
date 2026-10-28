FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 autoforge \
    && useradd --system --uid 10001 --gid autoforge --home-dir /app autoforge
WORKDIR /app
COPY --from=build --chown=autoforge:autoforge /workspace/target/*.jar app.jar
USER 10001:10001
EXPOSE 8089
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
