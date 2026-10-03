# Builds one of the example applications. Build context: the repository root.
#   docker build -f examples/Dockerfile --build-arg PROJECT=GnapResourceServer -t gnap-rs .
# Used by examples/docker-compose.yml.
ARG PROJECT

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG PROJECT
WORKDIR /repo
COPY Directory.Build.props ./
COPY src/ src/
COPY examples/${PROJECT}/ examples/${PROJECT}/
# No .git in the build context: Source Link is only needed for the NuGet packages.
RUN dotnet publish examples/${PROJECT}/${PROJECT}.csproj \
      --configuration Release --output /app \
      -p:EnableSourceLink=false -p:EnableSourceControlManagerQueries=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
ARG PROJECT
ENV APP_DLL=${PROJECT}.dll
WORKDIR /app
COPY --from=build /app ./
USER $APP_UID
ENTRYPOINT ["sh", "-c", "exec dotnet \"$APP_DLL\" \"$@\"", "--"]
