# node-jose-icon
아이콘 PDS(pds-for-nia)의 API 메시지를 암복호화 하기 위한 node-jose 의 수정 버전입니다.

---

# 시작하기
## Requirements

1. **Node**

node 실행 환경이 준비되어 있어야 합니다. 다음의 명령어로 설치된 node 의 버전을 확인할 수 있습니다.
본 샘플 코드는 v16.5.0 에서 테스트 되었습니다.
~~~
$ node -v
~~~

2. **Requirement**

package.json 에 다음의 의존성을 추가해야 합니다.
~~~
{
  "dependencies": {
    ...
    "node-jose-icon": "github:iconloop/node-jose-icon",
    ...
  }
}
~~~
~~~
$ npm install
~~~

필요한 경우 node-jose-icon 패키지는 다음의 커맨드로도 설치 할 수 있습니다.
~~~
$ npm install https://github.com/iconloop/node-jose-icon.git
~~~

3. **config/default.json**

설정 파일에 서버 정보가 기록되어 있어야 합니다. 위치는 config/default.json 입니다.

~~~
{
    "icon": {
        "uri": "http://pds-nia.iconscare.com",
        "method": "POST",
        "server_key": {
            "crv": "[CRV]",
            "kty": "[KTY]",
            "x": "[secret]",
            "y": "[secret]"
        }
    }
}
~~~


## RUN

다음의 샘플 코드와 같이 pds-for-nia 서버와 통신할 수 있습니다.
전체 Sample 코드와 응답 예시는 sample.js 를 참조해주세요.
~~~
const pds_client = require('node-jose-icon').icon;

data = [
    ["a@abc.com", "01012345678"],
    ["b@abc.com", "01011115678"],
    ["c@abc.com", "01022225678"],
    ["d@abc.com", "01033335678"]
]

pds_client.validation(data, function (response) {
    console.log("request with ", data)
    console.log("response is ", response)
})
~~~
