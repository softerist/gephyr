docker build --no-cache -t gephyr:latest -f docker/Dockerfile .
.\start-docker.ps1 restart -EnableAdminApi
.\start-docker.ps1 login
