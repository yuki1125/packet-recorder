# packet-recorder

指定したLinux Ethernet NICの送受信を、**capture filterなし**でPCAPNG／PCAPへ保存するロガーです。E1R、カメラ、CAN-Ethernet Gateway等の種類・IP・ポートを識別しません。

```text
Sensors → Switch → NIC ┬→ dumpcap/libpcap → PCAPNG / PCAP
                      └→ E1R / Camera applications
Python supervisor ─────→ 起動・停止・容量監視・metadata・終了統計
```

UDP socketで受けたpayloadに偽ヘッダーを付ける実装ではありません。RecorderはアプリケーションのUDPポートをbindせず、各アプリケーションと独立したプロセスで動作します。

## インストール

Python 3.10以上、Linux、`ip`（iproute2）、Wiresharkの`dumpcap`が必要です。終了後の統計集計を含め、Python本体は標準ライブラリだけを使います。

Ubuntuの例（管理者が実施）：

```bash
sudo apt-get update
sudo apt-get install wireshark-common iproute2
git clone https://github.com/yuki1125/packet-recorder.git
cd packet-recorder
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

高帯域データをPythonで1 packetずつ処理しないため、libpcapを利用するネイティブのdumpcapを採用しています。取得・ファイル書き込み・rotationは同じdumpcapプロセス内で行い、Pythonへpacketを転送しません。NumPyやセンサーdecoderへの依存はありません。Wireshark/dumpcap 3.6.2で検証しています。

## NICと権限

NICはPCをネットワークへ接続するインターフェースです。Linux上の名前は`eth0`、`enp4s0`、`eno1`等で、固定しません。

```bash
ip addr
ip link
python -m packet_recorder.interfaces
dumpcap -D
dumpcap -i enp4s0 -L
```

一覧はMAC、IPv4、link state、リンク種類を表示します。v1のcaptureはEthernetの`EN10MB`に限定します。`lo`や`any`、SocketCAN、複数NICは明示的なエラーです。無線monitor modeは設定しません。Ethernet形式を提供する無線interfaceでも、物理Ethernetと同一の意味にはなりません。

パケット取得には通常`CAP_NET_RAW`や`CAP_NET_ADMIN`、またはrootが必要です。推奨はディストリビューションのWireshark設定手順で**dumpcapだけ**にcapture権限を与え、Pythonとdecoderを一般ユーザーで動かすことです。Ubuntuでは管理者が`sudo dpkg-reconfigure wireshark-common`で非root captureを有効にし、必要なユーザーを`wireshark`グループへ追加した後に再ログインします。

手動capability設定が必要な管理環境では、管理者がdumpcapの実体パス・所有者・実行可能ユーザーを確認してから`sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap`を実行する方法があります。`getcap /usr/bin/dumpcap`で確認できます。全ユーザーにcapture権限を渡さないよう実行権限も管理してください。Python実行ファイルにcapabilityを付与しないでください。

一時的な管理者試験では`sudo /absolute/path/.venv/bin/python -m packet_recorder.record ...`も使用できますが、通常運用ではPython全体をrootにする必要はありません。プログラムはsudo、sudoers変更、setcap、sysctl変更を実行しません。capture権限の不足はdumpcapのエラーとして表示されます。

## 使用方法

```bash
python -m packet_recorder.record --interface enp4s0 --output-dir logs
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcapng
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcap
python -m packet_recorder.record --interface enp4s0 --output-dir logs --rotate-seconds 600
python -m packet_recorder.record --interface enp4s0 --output-dir logs --rotate-size-mb 1024
python -m packet_recorder.record --interface enp4s0 --buffer-mb 64 --min-free-gb 10 --duration 60
```

`--output`と`--output-dir`は排他です。省略すると`logs/`に保存します。形式は`--format pcapng|pcap`または明示したファイルの拡張子で指定し、不一致はエラーです。既定形式はPCAPNG。PCAPは単一interface向けの簡潔な形式、PCAPNGはinterface metadata・timestamp分解能・drop統計や将来の複数interfaceを扱える形式です。

| オプション | 既定値・意味 |
|---|---|
| `--interface` | 必須。内部ではリスト、v1では1個のみ |
| `--buffer-mb` | 64 **MiB**、dumpcapのbuffer要求値 |
| `--promiscuous` | 既定OFF、指定時ON |
| `--rotate-seconds` | 未指定は時間rotationなし |
| `--rotate-size-mb` | decimal MB、1 MB = 1,000,000 bytes、kBへ切り上げ |
| `--min-free-gb` | 10 **GiB**、0で閾値チェックを事実上無効化 |
| `--duration` | 未指定は手動停止まで継続 |
| `--dumpcap` | `dumpcap`。別パスを指定可能 |

capture filterのオプションはありません。`-s 0`でdumpcapの最大snaplenを要求します。現環境では262144 bytesです。metadataには実際のsnaplenと切り詰めpacket数を記録します。

自動生成時は**UTCの開始日**でディレクトリを決め、session名にUUIDの一部を含めます。日付をまたいでも同じsessionディレクトリです。

```text
logs/20260916/
  capture_143000_a1b2c3d4e5f6.json
  capture_143000_a1b2c3d4e5f6.stderr.log
  capture_143000_a1b2c3d4e5f6_00001_20260916143000.pcapng
  capture_143000_a1b2c3d4e5f6_00002_20260916144000.pcapng
```

rotationの末尾時刻はdumpcap側のタイムゾーンです。時間・サイズを併用すると先に到達した条件で切り替えます。サイズはpacket境界で超過する場合があります。ファイル数を制限する循環ringは使用せず、古いファイルを自動削除しません。既存出力・metadata・session prefixに衝突した場合は開始を拒否します。

## 容量、終了、統計

開始前と実行中1秒間隔で空き容量を調べ、下限未満なら警告して停止します。チェック間隔内の急増、他プロセスの書き込み、filesystem quota等は完全には予防できません。高帯域では十分な余裕を設けてください。要求bufferがOS/driver側で制限される場合があります。`net.core.rmem_max`等の関連設定を調べる場合も、管理者が対象capture方式への影響を確認してください。要求値と実効値は同一とは限りません。

Ctrl+C / SIGINT / SIGTERMでdumpcapへSIGINTを送り、最大10秒正常closeを待ちます。応答しなければ強制終了し、完全性を保証できない旨を記録します。SIGKILL、電源断、完全なdisk枯渇では正常closeや最終metadata保存を保証できません。

**capture停止時点でNIC／kernelに残る未配送packetの排出までは保証されません。** 試験では送信終了後にbuffer配送の猶予を置いています。drop=0も、回線上の全packetを受け取った証明ではありません。

終了後にコンテナを順次読み、packet件数・packet bytes・ファイル容量を別々に集計します。プロトコル解析は行いません。この集計は大きなcaptureでは時間がかかります。終了時刻と終了理由を先にmetadataへ保存します。

- `packet_count` / `captured_bytes`: 保存された件数とヘッダーを含むcaplenの合計。
- `file_bytes`: PCAP/PCAPNGコンテナの容量。packet bytesとは異なります。
- `kernel_drops`: dumpcap終了報告の`pcap:`値。capture用kernel bufferのdropで、NIC上流のlossとは異なります。
- `capture_drops`: 同じ報告の`dumpcap:`値。取得不能ならどちらもJSON `null`（UNSUPPORTED）。
- `flushed_drops` / `reported_interface_drops`: 終了報告の`flushed:` / `ps_ifdrop:`も保持し、非ゼロなら警告します。driverが未対応でもinterface dropが0を返す場合があり、0だけでNIC上流の無損失は確認できません。
- PCAPNGのInterface Statistics Blockは各ファイルに保存し、そのままmetadataに転記します。rotation間で累積値か区間値かを仮定して加算しません。
- dropが非ゼロなら`WARNING`を出します。件数不一致、切り詰め、ファイル破損も通知します。
- 平均packets/sとdecimal MB/sを終了時に表示します。時間はプロセス起動・停止待機を含み、最終ファイル集計時間は含みません。

終了コードは正常終了／手動停止が0、開始失敗・容量不足・capture異常・強制終了・検証異常が1、CLI引数エラーが2です。drop警告だけなら0なので、無損失を要求する運用ではmetadataも確認してください。

## 時刻と観測範囲

capture timestampはlibpcap/dumpcapが与えた値をそのまま保存します。PCAPNGのinterfaceごとの分解能を読み、metadataにも保持します。最初・最後のtimestampは精度を失わないよう秒の有理数文字列です。clock sourceは既定backendの情報だけでは特定できないため`unknown`とします。ナノ秒表現であってもナノ秒精度やハードウェアtimestampを保証しません。センサー内部時刻との同期にはPTP等を含めた別の設計が必要です。

PCに接続されたNICでcaptureできるのは、そのNICで実際に観測できる送受信frameのみです。通常のEthernet switchでは他ポート間だけで完結するunicast trafficは見えません。全sensor trafficが必要ならnetwork topology、port mirroring、SPAN、TAPを検討してください。promiscuous modeだけでswitchの全通信が見えるわけではありません。OFFはdumpcapがpromiscuousを要求しない意味であり、別プロセスがすでに有効にしている状態を解除しません。

NIC/OSによるchecksum offload、GRO/GSO、VLAN処理、FCS除去などの影響を受けます。保存対象はcapture backendが提供する実packetで、物理回線のビット列完全複製ではありません。必要な検証は管理者が行い、Recorderはoffload設定を自動変更しません。

## E1R併用と将来拡張

別ターミナル・別仮想環境で実行できます。

```bash
# Recorder側
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcapng
# 既存E1Rプロジェクト側
python -m e1r_decoder.live --bind-ip 0.0.0.0 --msop-port 6699 --difop-port 7788
python -m e1r_decoder.decode_pcap --pcap /absolute/path/logs/capture.pcapng
```

Recorderとdecoderは相互にimportせず、どちらかを停止しても他方は動作できます。既存decoderのPCAPNG/Ethernet対応を利用し、MSOP/DIFOP識別はdecoder側がport、長さ、magicを確認します。既存decoderのsource-port限定trafficへの対応範囲は変えません。

カメラは同NICで見えるEthernet packetとして保存され、Recorder変更は不要です。CAN-Ethernet Gatewayも同様です。`can0`のSocketCANは別interface・別link typeでありv1未実装です。将来はinterfacesリスト、backendの複数`-i`、PCAPNGのinterface IDごとの統計を拡張します。PCAPでの複数interfaceは対象外です。

## テスト

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

Linux実capture試験は明示実行です。`tshark`、`ping`、`ip`、rootでnetwork namespaceを作成できる環境と、既存E1Rコード・公開PCAPが必要です。テスト用仮想環境に`dpkt numpy`を導入します。

```bash
sudo apt-get install tshark iputils-ping
python -m pip install dpkt numpy
sudo /absolute/path/.venv/bin/python scripts/validate_linux.py \
  --e1r-project /absolute/path/robosense-e1r-decoder
```

使い捨てnamespace内にvethを作り、既存NICのcaptureやhost route変更は行いません。rootは隔離fixtureの作成・試験にのみ使用します。正常終了・試験例外では作成したnamespaceを削除します。強制kill時は`ip netns list`で`pr-a-*`／`pr-b-*`の残留を確認し、該当試験のものだけ管理者が削除してください。

検証結果は`validation-artifacts/`へ保存しGit対象外です。実施結果・制約は[VALIDATION.md](VALIDATION.md)を参照してください。

公式資料: [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html)、[capture privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges)、[libpcap statistics](https://www.tcpdump.org/manpages/pcap_stats.3pcap.html)。
