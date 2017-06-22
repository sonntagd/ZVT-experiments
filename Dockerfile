FROM perl:5.20

RUN cpanm IO::Socket::INET
RUN cpanm DDP
RUN apt-get update && apt-get install -y libpcap-dev
RUN cpanm -f Net::Pcap
RUN cpanm Net::Analysis
RUN cpanm AnyEvent
