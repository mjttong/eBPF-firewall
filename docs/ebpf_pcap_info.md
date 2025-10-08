# eBPF Packet Capture Project

## 개요

- eBPF 기반의 패킷 스니퍼  
- eBPF-go(libbpf)을 사용하여 L3, L4 패킷의 헤더 정보를 캡처하고 로깅  
- IPv6 미지원 (IPv4 전용)

## 환경

- Ubuntu 24.04
- WSL2 linux kernel 6.6.87

## eBPF 코드 (C)

- vmlinux.h 사용
- `ebpf_pcap.c`  
- TC hook에 attach  
- 패킷 파싱 후 `ringbuf`에 이벤트 저장, BTF 활용

- 파일명: `ebpf_pcap.c`
- 라이선스: GPL 명시
- 포함 헤더: `vmlinux.h`, `bpf/bpf_helpers.h`, `bpf/bpf_endian.h`
  - BTF: `vmlinux.h`를 통해 BTF(BPF Type Format)를 적극 활용 (CO-RE)
- Hook: TC hook에 attach
  - 모든 NIC를 대상으로 모니터링
  - `SEC("tc")` 사용
  - ingress, egress 모두 감시
- 통신 방식: `BPF_MAP_TYPE_RINGBUF` 타입의 `ringbuf` 맵을 사용하여 사용자 공간(go)으로 데이터 전송

### 데이터 구조 (C struct)

```c
struct packet_event {
    u64 ts_ns;            // 타임스탬프 (ns 단위)
    u8  protocol;         // L4 프로토콜 (TCP=6, UDP=17 등)
    u16 sport;            // 소스 포트
    u16 dport;            // 목적지 포트
    u32 saddr;            // 소스 IPv4 주소
    u32 daddr;            // 목적지 IPv4 주소
};
```

### 동작 로직

- 프로그램의 기본 반환값은 `TC_ACT_OK`로 하여, 어떤 경우에도 패킷을 드롭(drop)하지 않도록 한다.
- L2 이더넷 헤더를 파싱하여 프로토콜이 IPv4(`ETH_P_IP`)가 아니면 즉시 처리를 종료한다.
- L3 IP 헤더를 파싱한다.
- IP 단편화 패킷은 무시하고 처리를 종료한다.
- L4 프로토콜이 TCP 또는 UDP가 아니면 즉시 처리를 종료한다.
- L4 TCP/UDP 헤더를 파싱한다.
- 추출한 정보(타임스탬프, 프로토콜, IP, 포트)를 `packet_event` 구조체에 넣는다.
- 채워진 구조체를 `ringbuf`에 제출(submit)한다.
- 모든 과정에서 `skb` 버퍼의 경계를 넘지 않도록 안전하게 파싱한다.

## go 코드

- 파일명: `ebpf_pcap.go`
- eBPF 프로그램을 로드하고 `ringbuf`에서 이벤트 수신
- stdout 출력 및 `/var/log/ebpf.log` 저장

## 동작 플로우

1. CLI 실행 → `ebpf_pcap.c` 로드 및 TC hook attach
2. eBPF 코드 → 패킷 파싱 후 `ringbuf`에 push
3. Go 코드 → `ringbuf` 소비, stdout 및 로그 파일 기록

## 실행 방법

```bash
# 실행
$ sudo pcap-bpfcc
[+] eBPF packet capture started...
Captured packet: TCP 192.168.0.10:443 -> 192.168.0.20:53122
Captured packet: UDP 10.0.0.1:53 -> 10.0.0.5:52000
```

- 터미널에 CLI 명령 `ebpf-pcac`이라 입력 시 eBPF 프로그램 실행 시작 및 시작 문구 출력

```bash
# 종료 (Ctrl+C)
^C
[!] eBPF packet capture stopped.
```

- Ctrl + c로 종료, 종료 문구 출력

## 로그

- 기본 로그 경로: `/var/log/ebpf.log`
- stdout 출력과 동일한 형식으로 기록
