# backend/Dockerfile
FROM eclipse-temurin:21-jre

WORKDIR /app

# copia o jar já construído (assumindo que você faça mvn package localmente ou no CI)
COPY target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
