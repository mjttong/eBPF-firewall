FROM ubuntu:24.04

# 작업 디렉토리 생성
WORKDIR /ebpf-firewall

# 필수 파일 복사
COPY ./test/apt.sh ./apt.sh
COPY ./bin/ebpfw ./ebpfw

# 스크립트 실행 권한 부여
RUN chmod +x ./apt.sh && \
    chmod +x ./ebpfw \

# 패키지 설치 스크립트 실행
RUN ./apt.sh

# 기본 명령어 (컨테이너 실행 시)
CMD ["/bin/bash"]
