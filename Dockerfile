FROM perl:5.20

RUN cpanm IO::Socket::INET
RUN cpanm DDP

