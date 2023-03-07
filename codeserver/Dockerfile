FROM linuxserver/mods:code-server-docker as code-server-docker
FROM linuxserver/mods:universal-docker-in-docker as universal-docker-in-docker
FROM linuxserver/mods:code-server-golang-1.17.2 as golang-in-docker
FROM lscr.io/linuxserver/code-server
RUN apt-get update
RUN apt-get install -y vim
RUN     apt-get install -y \
        btrfs-progs \
        ca-certificates \
        curl \
        e2fsprogs \
        iptables \
        openssh-client \
        openssl \
        pigz \
        xfsprogs \
        xz-utils
RUN apt-get install -y nmap telnet emacs

RUN apt-get install -y wget build-essential iputils-ping
RUN apt-get update && apt install -y bsdtar curl

# code-server-docker
COPY --from=code-server-docker / /
#RUN echo $USER
#RUN ls -la /etc/cont-init.d/98-docker
#RUN chmod 777 /etc/cont-init.d/98-docker
#RUN ls -la /etc/cont-init.d/
#RUN sed '1,2d' /etc/cont-init.d/98-docker >> /etc/cont-init.d/98-docker_tmp && mv /etc/cont-init.d/98-docker_tmp /etc/cont-init.d/98-docker
#RUN ex -s -c '1d1|x' /etc/cont-init.d/98-docker
#RUN chmod 777 /etc/cont-init.d/98-docker
#RUN /etc/cont-init.d/98-docker
#RUN rm /etc/cont-init.d/98-docker

COPY --from=universal-docker-in-docker / /
COPY --from=golang-in-docker / /


RUN rm -Rf /etc/cont-init.d/95-apt-get
#RUN /etc/cont-init.d/95-apt-get
#RUN cat /etc/cont-init.d/98-docker-in-docker
#RUN apt-get install -y vim
#RUN ls -la /etc/cont-init.d/
#RUN ex -s -c '10d11|x' /etc/cont-init.d/98-docker-in-docker
#RUN sed '10,20d' /etc/cont-init.d/98-docker-in-docker >> /etc/cont-init.d/98-docker-in-docker_tmp && mv /etc/cont-init.d/98-docker-in-docker_tmp /etc/cont-init.d/98-docker-in-docker
#RUN cat /etc/cont-init.d/98-docker-in-docker
#RUN cat /etc/cont-init.d/98-docker-in-docker
#RUN chmod 777 /etc/cont-init.d/98-docker-in-docker
#RUN /etc/cont-init.d/98-docker-in-docker

#RUN sed '1,2d' /etc/cont-init.d/98-golang >> /etc/cont-init.d/98-golang_tmp && mv /etc/cont-init.d/98-golang_tmp /etc/cont-init.d/98-golang
#RUN chmod 777 /etc/cont-init.d/98-golang
#RUN /etc/cont-init.d/98-golang
#RUN cat /etc/cont-init.d/98-golang
#RUN rm /etc/cont-init.d/98-golang
#RUN rm -Rf /etc/cont-init.d/95-apt-get
#RUN mkdir -p /root/.local/share/code-server/extensions
#run wget https://github.com/microsoft/vscode-cpptools/releases/download/1.7.0/cpptools-linux-aarch64.vsix
#WORKDIR /extensions/
#RUN wget https://github.com/microsoft/vscode-cpptools/releases/download/1.7.0/cpptools-linux.vsix
#RUN wget https://github.com/golang/vscode-go/releases/download/v0.28.1/go-0.28.1.vsix
#RUN echo "#!/usr/bin/with-contenv bash" >> /etc/cont-init.d/98-extensions 
#RUN echo "code-server --extensions-dir /config/extensions --install-extension /extensions/cpptools-linux.vsix" >> /etc/cont-init.d/98-extensions 
#RUN echo "code-server --extensions-dir /config/extensions --install-extension /extensions/go-0.28.1.vsix" >> /etc/cont-init.d/98-extensions 

#RUN /usr/local/go/bin/go get -g -v golang.org/x/tools/gopls
#
#RUN code-server     --install-extension /cpptools-linux-aarch64.vsix 
#RUN code-server --install-extension cpptools-linux-aarch64.vsix
