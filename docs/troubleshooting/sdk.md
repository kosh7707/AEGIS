# SDK 등록 문제 해결

SDK 등록 화면의 오류 링크는 이 문서의 오류 코드로 연결된다. 먼저 오류 화면의 기술 상세와 상관관계 ID를 기록하고, 설치형 SDK라면 해당 SDK의 `install.log`를 확인한다. 재시도는 화면에서 제공될 때만 실행하며 업로드 디렉터리를 직접 삭제하거나 초기화하지 않는다.

## 빠른 진단

| 오류 코드 | 의미 | 우선 조치 |
| --- | --- | --- |
| [`UPLOAD_INVALID_INPUT`](#upload-invalid-input) | 업로드 입력이 유효하지 않음 | 파일 선택과 요청 형식을 확인한다. |
| [`EXTRACT_ARCHIVE_EMPTY`](#extract-archive-empty) | 압축 파일에 항목이 없음 | 원본 압축 파일의 내용을 확인한다. |
| [`EXTRACT_UNSAFE_ENTRY`](#extract-unsafe-entry) | 압축 경로가 SDK 경계를 벗어남 | 절대 경로, `..`, 외부 심볼릭 링크를 제거해 다시 패키징한다. |
| [`EXTRACT_FAILED`](#extract-failed) | 압축 목록 조회 또는 해제 실패 | 파일 형식과 손상 여부, `tar`/`unzip` 사용 가능 여부를 확인한다. |
| [`INSTALL_ETXTBSY`](#install-etxtbsy) | 설치 파일이 다른 프로세스에서 사용 중 | 파일 쓰기가 끝난 뒤 잠시 기다리고 재시도한다. |
| [`INSTALL_PROCESS_FAILED`](#install-process-failed) | 설치 프로그램이 실패 코드로 종료됨 | `install.log`의 stderr와 설치 프로그램 요구사항을 확인한다. |
| [`INSTALL_TIMEOUT`](#install-timeout) | 설치 제한 시간을 초과함 | 로그의 마지막 진행 지점과 시간 제한 설정을 확인한다. |
| [`VERIFY_PATH_ESCAPED`](#verify-path-escaped) | SDK 루트가 업로드 저장소 밖을 가리킴 | SDK를 프로젝트에 다시 등록한다. |
| [`VERIFY_PATH_MISSING`](#verify-path-missing) | 검증할 SDK 경로가 없음 | 보존된 업로드 산출물과 저장 공간 상태를 확인한다. |
| [`VERIFY_CONTENT_EMPTY`](#verify-content-empty) | SDK에 보이는 파일이 없음 | 숨김 파일만 있는지 확인하고 완전한 SDK를 다시 올린다. |
| [`VERIFY_PROFILE_PATH_INVALID`](#verify-profile-path-invalid) | 프로필의 sysroot/include/setup 경로가 잘못됨 | 프로필 경로를 SDK 루트 기준 상대 경로로 수정한다. |
| [`ANALYZE_UNAVAILABLE`](#analyze-unavailable) | SDK 분석 서비스를 사용할 수 없음 | Build Agent 상태를 확인한 뒤 분석을 재시도한다. |
| [`RETRY_UNSUPPORTED_PHASE`](#retry-unsupported-phase) | 현재 단계는 재시도를 지원하지 않음 | 실패 단계와 화면의 재시도 가능 여부를 확인한다. |
| [`RETRY_QUOTA_EXCEEDED`](#retry-quota-exceeded) | 재시도 한도 3회를 소진함 | 반복 실패 원인을 해결한 뒤 새 등록을 시작한다. |
| [`RETRY_COOLDOWN_ACTIVE`](#retry-cooldown-active) | 30초 재시도 대기 시간이 남음 | 대기 시간이 지난 뒤 한 번만 재시도한다. |
| [`RETRY_ARTIFACT_UNAVAILABLE`](#retry-artifact-unavailable) | 재시도할 SDK 산출물이 없거나 만료됨 | 원본 SDK를 새로 등록한다. |
| [`UNKNOWN_SDK_ERROR`](#unknown-sdk-error) | 분류되지 않은 검증 오류 | 기술 상세와 상관관계 ID로 백엔드 로그를 조회한다. |

안전한 로컬 진단 명령:

```bash
df -h
file /path/to/sdk-archive
tar -tf /path/to/sdk.tar.gz
unzip -Z1 /path/to/sdk.zip
```

`tar -tf`와 `unzip -Z1`은 목록만 읽는다. 설치 파일을 직접 실행하거나 업로드 저장소를 수정하지 않는다.

<a id="upload-invalid-input"></a>
## UPLOAD_INVALID_INPUT

파일이 없거나 폴더 업로드의 상대 경로가 비어 있거나 안전하지 않을 때 발생한다. 업로드 선택을 다시 확인하고, 폴더 항목에는 절대 경로나 `..`가 포함되지 않게 한다.

<a id="extract-archive-empty"></a>
## EXTRACT_ARCHIVE_EMPTY

`tar -tf` 또는 `unzip -Z1`로 원본에 실제 항목이 있는지 확인한다. 비어 있다면 SDK 원본에서 다시 압축한다.

<a id="extract-unsafe-entry"></a>
## EXTRACT_UNSAFE_ENTRY

절대 경로, 상위 디렉터리 이동, 드라이브 문자 또는 SDK 밖을 가리키는 심볼릭 링크가 감지됐다. 원본 트리를 안전한 상대 경로만 포함하도록 다시 패키징한다.

<a id="extract-failed"></a>
## EXTRACT_FAILED

확장자와 실제 파일 형식이 일치하는지 `file`로 확인하고 목록 조회 명령의 오류를 확인한다. 손상된 파일이면 원본에서 다시 받거나 다시 압축한다.

<a id="install-etxtbsy"></a>
## INSTALL_ETXTBSY

업로드 직후 설치 파일을 쓰는 프로세스가 아직 닫히지 않은 상태다. 서비스는 짧게 자동 재시도한다. 계속 실패하면 파일 전송이 끝났는지 확인한 뒤 화면에서 재등록한다.

<a id="install-process-failed"></a>
## INSTALL_PROCESS_FAILED

`install.log`의 마지막 stderr, 실행 권한, 설치 프로그램이 요구하는 시스템 도구를 확인한다. 설치는 프로젝트 전용 HOME과 임시 디렉터리에서 비대화식 `--prefix` 방식으로 실행된다.

<a id="install-timeout"></a>
## INSTALL_TIMEOUT

기본 제한 시간은 30분이다. `install.log`의 마지막 출력이 계속 진행 중인지 멈췄는지 확인한다. 운영자가 제한 시간을 조정할 때는 `AEGIS_SDK_INSTALL_TIMEOUT_MS`를 양의 밀리초 값으로 설정하고 서비스를 정상 절차로 재기동한다.

<a id="verify-path-escaped"></a>
## VERIFY_PATH_ESCAPED

검증 대상 경로가 AEGIS 업로드 루트 밖으로 계산됐다. 저장소 경로를 수동으로 고치지 말고 원본 SDK를 프로젝트에 다시 등록한다.

<a id="verify-path-missing"></a>
## VERIFY_PATH_MISSING

등록 레코드가 가리키는 SDK 산출물이 없다. `df -h`로 저장 공간을 확인하고, 외부 정리 작업이 파일을 옮겼는지 확인한 뒤 원본을 다시 등록한다.

<a id="verify-content-empty"></a>
## VERIFY_CONTENT_EMPTY

SDK 루트에 숨김 파일을 제외한 내용이 없다. 헤더, 라이브러리 또는 툴체인이 포함된 완전한 SDK를 다시 업로드한다.

<a id="verify-profile-path-invalid"></a>
## VERIFY_PROFILE_PATH_INVALID

`environmentSetup`, `sysroot`, `includePaths` 중 하나가 SDK 루트 밖을 가리키거나 존재하지 않는다. SDK 내부에 실제로 존재하는 상대 경로로 프로필을 수정한다.

<a id="analyze-unavailable"></a>
## ANALYZE_UNAVAILABLE

Build Agent가 SDK 메타데이터 분석 요청을 처리하지 못했다. 서비스 상태와 네트워크 연결을 확인한 뒤 분석 단계부터 재시도한다. 원본 산출물이 보존돼 있어야 한다.

<a id="retry-unsupported-phase"></a>
## RETRY_UNSUPPORTED_PHASE

현재 실패 단계가 분석 또는 검증 재시도 대상이 아니다. 화면에 표시된 단계와 재시도 가능 상태를 확인하고, 지원되지 않으면 새 등록을 사용한다.

<a id="retry-quota-exceeded"></a>
## RETRY_QUOTA_EXCEEDED

등록 한 건당 재시도 한도는 3회다. 같은 등록을 반복 호출하지 말고 기술 상세와 로그에서 원인을 해결한 뒤 원본으로 새 등록한다.

<a id="retry-cooldown-active"></a>
## RETRY_COOLDOWN_ACTIVE

재시도 사이에는 30초 대기 시간이 있다. 대기 후 화면 상태를 새로 확인하고 한 번만 재시도한다.

<a id="retry-artifact-unavailable"></a>
## RETRY_ARTIFACT_UNAVAILABLE

재시도에 필요한 산출물이 없거나 보존 기간을 지났다. 파일 시스템을 임의로 복구하지 말고 검증된 원본 SDK를 새로 등록한다.

<a id="unknown-sdk-error"></a>
## UNKNOWN_SDK_ERROR

기술 상세, 실패 시각, 상관관계 ID를 함께 기록해 백엔드 로그와 대조한다. 원인을 확인하기 전 업로드 디렉터리를 삭제하거나 레지스트리 상태를 직접 수정하지 않는다.
