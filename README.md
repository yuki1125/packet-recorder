# packet-recorder

LinuxのNICで観測できる全送受信パケットを、Ethernetヘッダーと取得時刻を含めてPCAPNG／PCAPに保存します。LiDAR、Ethernetカメラ、CAN-Ethernet Gatewayなどの通信記録に使えます。

対応環境はPython 3.10以上のLinux、記録対象は1つのEthernet NICです。パケットの取得・保存には、高帯域通信を低負荷で扱えるdumpcap/libpcapを使用します。

## 1. インストール

Ubuntuの例です。

```bash
sudo apt-get update
sudo apt-get install wireshark-common iproute2 python3-venv
git clone https://github.com/yuki1125/packet-recorder.git
cd packet-recorder
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

パケット取得にはOSのcapture権限が必要です。通常はdumpcapに権限を与え、Recorderを一般ユーザーで実行します。Ubuntuでは次の設定画面で一般ユーザーのcaptureを有効にし、使用するユーザーを`wireshark`グループへ追加して再ログインします。

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$USER"
```

管理者が手動で設定する環境では、dumpcapの実行権限を利用者に限定したうえで`CAP_NET_RAW`・`CAP_NET_ADMIN`を付与します。詳細は[Wiresharkの権限設定](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges)を参照してください。

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
```

一時的な管理者試験では、記録コマンドの`python`を`sudo /absolute/path/.venv/bin/python`に置き換えて実行できます。

## 2. NICを選ぶ

NICはPCをネットワークへ接続するインターフェースです。次のコマンドで名前、MACアドレス、IPv4アドレス、接続状態を確認します。

```bash
python -m packet_recorder.interfaces
```

Linux標準コマンドでは`ip addr`でアドレス、`ip link`でリンク状態を確認できます。以降の例ではNIC名を`enp4s0`としています。実際の名前に置き換えてください。

## 3. 記録する

```bash
python -m packet_recorder.record --interface enp4s0 --output-dir logs
```

**Ctrl+Cで停止**します。ファイルを閉じた後、記録件数・転送量・drop統計を表示します。SIGINT／SIGTERMによる停止にも対応しています。大きな記録では終了時の集計に時間がかかります。

保存先には、開始日（UTC）のフォルダーと一意なファイル名が作られます。

```text
logs/20260916/
  capture_143000_a1b2c3d4e5f6.pcapng
  capture_143000_a1b2c3d4e5f6.json
  capture_143000_a1b2c3d4e5f6.stderr.log
```

PCAPNGは通信データ、JSONは設定・開始終了時刻・統計、stderr.logはdumpcapの実行ログです。

### 保存先と形式を指定する

```bash
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcapng
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcap
```

標準形式のPCAPNGは、interface情報や時刻の分解能、drop統計を保持できます。PCAPは単一interface向けの簡潔な形式です。どちらもWiresharkで開けます。

`--output`はファイル名、`--output-dir`は自動命名する保存先を指定します。形式は拡張子または`--format pcapng|pcap`で選び、両方指定する場合は一致させます。

### 長時間の記録を分割する

10分ごとにファイルを切り替える例です。

```bash
python -m packet_recorder.record --interface enp4s0 --output-dir logs --rotate-seconds 600
```

サイズで分割する場合は`--rotate-size-mb 1024`を指定します。時間とサイズを併用すると、先に到達した条件で切り替えます。各ファイル名には連番と作成時刻が付きます。

### 主な設定

| オプション | 動作・既定値 |
|---|---|
| `--buffer-mb 64` | capture bufferの要求サイズ。既定64 MiB |
| `--min-free-gb 10` | 空き容量が指定値を下回ると停止。既定10 GiB |
| `--promiscuous` | promiscuous modeを要求。既定OFF |
| `--duration 60` | 指定秒数で終了。省略時は手動停止まで継続 |
| `--rotate-seconds 600` | 指定秒数ごとに新しいファイルへ切り替え |
| `--rotate-size-mb 1024` | 指定サイズごとに切り替え。1 MB = 1,000,000 bytes |

空き容量は開始前と実行中1秒間隔で確認します。記録量に応じて停止閾値を大きく設定してください。既存の記録は保持され、出力名の衝突時は開始を拒否します。

## 4. 結果を確認する

PCAPNG／PCAPをWiresharkで開くと、送受信パケットと取得時刻を確認できます。終了時の表示とJSONでは、次の項目を確認します。

| 項目 | 内容 |
|---|---|
| `packet_count` | 保存されたパケット数 |
| `captured_bytes` | ヘッダーを含むパケットの合計bytes |
| `file_bytes` | 記録ファイルの合計サイズ |
| `kernel_drops` | kernelのcapture bufferで報告されたdrop |
| `capture_drops` | dumpcap内部で報告されたdrop |
| `average_packets_per_second` | 平均パケット数／秒 |
| `average_mb_per_second` | 平均転送量（MB／秒） |

dropの取得不能値は`null`、非ゼロ値は`WARNING`で表示します。dropが出たら、buffer、ディスク書き込み速度、入力帯域を確認してください。実効bufferサイズはOS・driverにも依存します。`net.core.rmem_max`等のOS設定を調整する場合は、管理者がcapture方式への適用を確認します。

終了コードは正常終了・手動停止が0、記録エラー・容量不足が1、引数エラーが2です。drop警告だけの場合は0のため、自動運用ではJSONの統計も確認してください。

## 5. E1R decoderと併用する

Recorderと既存E1R decoderを、それぞれの環境・別ターミナルで起動します。

```bash
# Recorder側
python -m packet_recorder.record --interface enp4s0 --output logs/capture.pcapng

# E1Rプロジェクト側
python -m e1r_decoder.live --bind-ip 0.0.0.0 --msop-port 6699 --difop-port 7788
```

両方を独立して起動・停止できます。記録したファイルから点群を復号する場合は、E1R側で次を実行します。

```bash
python -m e1r_decoder.decode_pcap --pcap /absolute/path/logs/capture.pcapng
```

## 記録対象と運用上の注意

- **観測範囲**：指定NICで観測できる通信が対象です。switchの他ポート間の通信も集める場合は、port mirroring（SPAN）やTAPで対象NICへ届ける構成が必要です。
- **CAN**：CAN-Ethernet GatewayはEthernet通信として記録できます。`can0`を使うSocketCANや複数NICの同時記録は将来の対応範囲です。
- **時刻**：capture timestampと分解能を保存します。clock sourceは`unknown`として記録します。センサー間の時刻比較には、別途同期状態の確認が必要です。
- **終了境界**：送信終了後にbuffer配送の時間を確保してからRecorderを停止してください。終了時にNIC／kernelに残っているパケットは記録から漏れる場合があります。
- **実機検証**：NIC offloadやFCS除去などが記録内容に影響します。必要な帯域・記録内容は実際のNICとセンサーで確認してください。

## 検証・開発

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

WSLの仮想Ethernetで、PCAP／PCAPNG、ファイル分割、E1R同時受信・offline復号を検証しています。実capture試験の結果と制約は[VALIDATION.md](VALIDATION.md)、captureツールの仕様は[dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html)を参照してください。
