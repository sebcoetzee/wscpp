FROM mcr.microsoft.com/devcontainers/base:jammy

RUN sudo -E apt update && \
    sudo -E apt install -y build-essential manpages-dev g++-12 cmake python3 python3-pip && \
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 10 && \
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 10

RUN python3 -m pip install conan