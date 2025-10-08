# eBPF 개발 환경 구성

## eBPF 구현 방식

### libbcc

- BPF compiler collection
- libbpf에 비해 비교적 오래된 eBPF 구현 방식
- 클라이언트 코드 내에 문자열로 C 코드를 포함
- 런타임 컴파일
  - eBPF 프로그램 실행 시 clang, llvm으로 컴파일 진행
- 의존성
  - eBPF 프로그램 내에 clang, llvm 라이브러리가 포함되어야 함
  - eBPF 프로그램 내에 커널 헤더 패키지가 포함되어야 해 커널 의존성 존재
- 리소스 소모
  - 실행 시 반드시 clang, llvm을 통한 컴파일이 진행되기 때문에 리소스 소모가 큼

### libbpf

- 사전 컴파일
  - 실행 전 미리 C 코드를 컴파일해 ELF 바이너리 파일 생성
  - 실행 시 해당 바이너리 파일을 로드, libbpf가 약간의 재배치만 수행
- 의존성 제거
  - 사전 컴파일이 진행되기 때문에 런타임 환경에서 clang, llvm 불필요
  - vmlinux.h, BTF를 통해 커널 타입을 런타임에 해결해 커널 의존성 제거
  - CO-RE(Compile Once, Run Everywhere)를 통해 한 번 컴파일한 바이너리가 여러 커널 버전에서 작동

## libbcc + wsl 환경의 한계

### libbcc의 단점

- wsl은 일반적인 네이티브 리눅스 환경이 아니기 때문에 커널 헤더가 불완전
  - apt 패키지 관리자를 통한 커널 설치 불가능
  - github에서 커널 수동 설치가 필요
- libbcc는 커널 헤더 패키지가 eBPF 프로그램 내에 포함되어야 해 커널 의존성이 큼
  - wsl의 커널 불완전성으로 개발 환경 구성이 번거로움
  - bcc로 eBPF 프로그램 개발 시 wsl 커널 헤더에 의존하는 이식성, 호환성이 매우 낮은 프로그램 생성
- bcc는 C 코드를 문자열로 포함해 불편함

### libbpf 전환 시 장점 & 단점

- vmlinux.h를 통해 wsl 커널 헤더에 의존하지 않는 eBPF 환경 구성 가능
- 클라이언트 코드와 C 코드가 분리되어 개발이 매우 편리
- 단, 현재 bcc에서 클라이언트 코드로 python을 사용했는데, go로 전환하는 것이 편리해보임
  - python-libbpf 환경은 아직 개발 중으로 불완전한 상태
    - <https://github.com/pythonbpf/pylibbpf>
  - eBPF-go는 libbpf 환경에서 많이 사용하는 도구로, 매우 편리하고 완성도가 높으며 생태계가 활발
    - <https://github.com/cilium/ebpf>
- 결론적으로 wsl 환경 제약 극복과 각종 편의성을 위해 eBPF-go를 사용하기로 결정

## libbpf python vs go

### eBPF 프로그램 구조

- eBPF 프로그램
  - C 코드로 작성
  - 커널 내부에서 실행
  - 커널 내부에서 얻은 정보를 map에 저장해 클라이언트로 전달 가능
- 클라이언트 프로그램
  - 자유롭게 언어 선택
  - eBPF 프로그램을 부착, 로드, 관리
  - eBPF 프로그램에 map에 전달한 데이터를 가져와 출력, 처리 등의 과정을 진행
  - 추가적인 클라이언트 로직 포함 가능
- libbcc의 경우 python을, libbpf의 경우 go, rust를 주로 사용

### eBPF 프로그램 구현

- eBPF 프로그램
  - C 코드로 구현
  - C 코드를 컴파일해 오브젝트 파일 생성
- 클라이언트 프로그램
  - 오브젝트 파일을 기반으로 eBPF 프로그램을 로드하는 코드 생성
  - 데이터 처리 등의 클라이언트 로직 추가

### eBPF-go

- eBPF-go는 bpf2go를 통해 clang으로 C 코드를 자동으로 컴파일, 오브젝트 파일을 생성
- bpf2go는 BPF 프로그램을 로드하는 go 코드 생성
- 사용자는 C 코드로 eBPF 프로그램을, go 코드로 클라이언트 로직만을 작성하면 되기 때문에 매우 편리
