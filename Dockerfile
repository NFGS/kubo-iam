# syntax=docker/dockerfile:1.7

# ---------- Etapa 1: compilacion ----------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

COPY pom.xml .
COPY src ./src

RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -q package -DskipTests

# ---------- Etapa 2: ejecucion ----------
FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache wget curl \
 && addgroup -S kubo && adduser -S -G kubo -u 1000 kubo

WORKDIR /app
COPY --from=build --chown=kubo:kubo /build/target/kubo-iam-*.jar app.jar

ENV JAVA_TOOL_OPTIONS="-Xmx256m -XX:MaxMetaspaceSize=128m"
EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=5 \
  CMD wget -qO- http://localhost:8081/api/v1/health || exit 1

# El servicio corre sin privilegios.
USER kubo

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
