FROM ubuntu:jammy

# mirror.nju.edu.cn/ubuntu
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak
RUN sed -i /etc/apt/sources.list -e "s/archive.ubuntu.com/mirror.nju.edu.cn/g"
RUN apt-get update

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y build-essential wget zip pkgconf zlib1g zlib1g-dev libzstd1 meson\
	ninja-build doxygen bzip2 flex graphviz libbz2-dev libssl-dev libncurses5-dev libsqlite3-dev libreadline-dev\
	libtk8.6 libgdm-dev libdb4o-cil-dev libpcap-dev

# python 3.11.1
RUN wget https://ghproxy.net/https://github.com/python/cpython/archive/refs/tags/v3.11.1.zip -O /tmp/v3.11.1.zip
RUN	cd /tmp && unzip v3.11.1.zip
RUN cd /tmp/cpython-3.11.1 && ./configure --enable-optimizations && make -j 32 && make install

RUN pip3 install angr z3-solver bz2file pydot graphviz angr iced_x86 pyelftools pyinstrument timeout_decorator

# libdwarf 0.5.0
RUN wget https://ghproxy.net/https://github.com/davea42/libdwarf-code/archive/refs/tags/v0.5.0.zip -O /tmp/v0.5.0.zip
RUN cd /tmp && unzip v0.5.0.zip && mkdir /tmp/build
RUN cd /tmp/build && meson /tmp/libdwarf-code-0.5.0 && ninja && ninja install && ninja test
