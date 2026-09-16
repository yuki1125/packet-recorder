# Validation — 2026-09-16

## 結果

```text
Raw Ethernet capture:
PASS

Capture without protocol filter:
PASS

PCAPNG output:
PASS

Wireshark compatibility:
PASS

Packet timestamps:
PASS

File rotation:
PASS

Capture statistics:
PASS

Kernel drop monitoring:
PASS

Disk free-space monitoring:
PASS

Concurrent E1R decoder:
PASS

E1R offline decode from recorded file:
PASS

Multi-interface ready architecture:
YES

SocketCAN recording:
NOT IMPLEMENTED
```

PASSの範囲は以下のWSL/veth試験です。物理NIC、E1R実機、GigE Vision cameraの実測を意味しません。

## 環境と手順

- Windows上のWSL2 Ubuntu 22.04、Python 3.10.12。
- Kernel `6.18.33.2-microsoft-standard-WSL2`。
- dumpcap/tshark 3.6.2、capture buffer要求64 MiB、promiscuous OFF。
- 2個の隔離network namespaceをvethで接続。`192.0.2.0/24`と`fd00:1234::/64`をfixture内のみで使用。
- `scripts/validate_linux.py`で実際のUDP/TCP送受信、ARP、ICMP、IPv6を生成。host NICは記録していない。
- 出力はWSLから見たWindowsファイルシステム上。root実行は隔離試験用で、運用時のPython root実行は必須ではない。
- テストに必要なWireshark toolsとPython仮想環境を導入。capability、sudoers、sysctl、既存NIC設定は変更していない。

## 自動試験

`python -m pytest -q`: **19 passed**。

CLI排他・形式推論・不正引数、フィルタ不使用、非循環rotation、既存ファイル保護、開始前／実行中の容量不足、NIC消失、capture異常、正常／強制停止、未知drop、非ゼロdrop警告、PCAP破損、PCAPNG両endian・十進／二進timestamp分解能・ISBを検証。

独立パッケージとしてeditable install、CLI help、interface一覧の実行も成功。

## 実capture

最終全ケース実行の証跡: `validation-artifacts/20260916_233413/3d52ff5c/results.json`。
実captureファイル・詳細ログ・IP/MACを含むsession metadataはローカル保存のみとし、Gitへは含めない。

| ケース | 保存packet数 | ファイル数 | kernel / capture drops | 結果 |
|---|---:|---:|---|---|
| PCAPNG | 130 | 1 | 0 / 0 | PASS |
| PCAP | 122 | 1 | 0 / 0 | PASS |
| 1秒rotation | 123 | 5 | 0 / 0 | PASS |
| 0.05 MB rotation | 120 | 3 | 0 / 0 | PASS |
| 20,000 packet追加burst | 20,121 | 1 | 0 / 0 | PASS |

各ケースでUDP 6699／7788／5000／6000、TCP、ARP、ICMP、IPv6を確認。送信側・受信側のIPv4、Ethernetのsource/destination、payloadをtsharkと既存readerで確認。全ファイルで切り詰めpacketは0。PCAPNGは1 ns表現、PCAPは1 μs表現を確認。これは時計の実精度を示すものではない。

全rotationファイルをtsharkで読み込み、既存E1R offline decoderでも読み込めた。Wireshark互換性のPASSは同系列tsharkでの実読み込みに基づき、GUIの目視試験ではない。

追加burstは1,024-byte UDP payloadを20,000件、送信ループ約0.0557秒で投入。保存された連番が0〜19,999で重複・欠落なし。capture全体で21,445,991 bytesを保存。これは仮想NIC・短時間burstの結果であり、物理回線速度や連続disk帯域の保証ではない。

SIGINTとSIGTERM双方で正常close・終了統計・metadata・終了コード0を確認。指定最小空き容量を実際の容量より大きくした試験では、captureを開始せず終了コード1・理由metadataを確認。実行中の閾値超過は単体試験で注入し、停止を確認した。

## E1R互換性と独立性

既存E1Rプロジェクトを変更せず使用。公開PCAPから取り出したMSOP 100件と、既存decoderの形式に合わせた合成DIFOP 1件をUDPで送信した。送信側が作ったUDP通信をNICで実captureしたもので、Recorderがヘッダーを再構築したものではない。

5ケースすべてでlive decoderと記録ファイルのoffline decoder双方が`valid_msop=100`、`valid_difop=1`。E1R payloadは元データとの一致を確認。これは完全なスキャン列ではないためpartial frameやsequence gapが出ることは正常。

live decoder終了後もRecorderが別ポート・ping等を記録し続けることを確認。逆方向の独立停止試験ではRecorderだけを途中停止し、live decoderはその後の第2送信を受信して`valid_msop=200`、`valid_difop=2`で完了した。

## Known limitations

- 実機E1R、物理NIC、長時間連続capture、カメラ、SocketCAN、複数interfaceは未検証。SocketCAN／複数interfaceはv1では明示的に拒否する。
- capture clock sourceは未特定。hardware timestampやセンサー間同期は保証しない。
- 正常停止はファイルcloseを保証するための制御で、NIC/kernelに残る未配送packetの完全な排出を保証しない。最初の試験で送信直後の停止による未記録を確認し、試験の測定区間には送信終了後1.5秒の配送猶予を設けた。
- ARPはcacheがあると毎回発生しないため、ケースごとにfixture内のneighbor cacheをクリアした。WSL DrvFSで生成直後のログreadが一時的にENODATAとなる現象は、ハーネスの待機処理でretryする。
- dropは観測点に依存し、上流switch/NICで失われたpacketすべてを検出できるわけではない。非ゼロdropの警告は注入試験で検証し、実負荷試験でdrop発生を意図的に誘発してはいない。
- SIGKILL、電源断、disk完全枯渇時の修復機能はない。容量チェックには1秒の間隔があり、余裕のある閾値が必要。
- 終了後のコンテナ走査はbounded memoryだが、全ファイルを読み返すため大容量では時間がかかる。
- dumpcapのstderr統計形式が変わった場合、未知の統計はnullとして扱う。3.6.2で実検証。PCAPNGのISBはファイル単位で保持し、意味が曖昧な累積値を加算しない。
- Linux native capture専用。WSLが見られるtrafficはWSLのinterfaceへ到達したものに限られ、Windows側の全NIC通信を見られるとは限らない。

GitHubへの転送は接続済みGitHub APIを使用。ローカルGitのCLI認証情報は新規作成・保存しない。
