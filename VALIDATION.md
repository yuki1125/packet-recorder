# Validation — v0.2.0 / 2026-09-16

## Windows対応

Windowsネイティブ実行向けに、Wiresharkの自動検出、Npcapのcapture IDと日本語NIC名の対応付け、非表示の専用consoleを利用した正常停止を追加した。

| 検証 | 結果 |
|---|---|
| Windows / Python 3.12.14 単体・プロセス試験 | **28 passed** |
| Linux / Python 3.10.12 回帰単体試験 | **26 passed, 2 skipped**（Windows専用試験） |
| Windows実NICのGUID・名称・MAC・IPv4・状態取得 | PASS（読み取りのみ） |
| Windowsで2つの子プロセスの片方だけ正常停止 | PASS |
| Windowsの容量低下による子プロセス停止・metadata確定 | PASS（合成コンテナのfixture） |
| 日本語の保存パス、依存ツール不足のエラー表示 | PASS |
| Windowsでwheel作成、停止helperの同梱確認 | PASS |
| WindowsのNpcapによる実capture | **未実施**：利用者の指定によりWireshark／Npcapの導入は後日 |

Windowsの停止試験は実際のWindowsプロセスとconsole制御を使ったもの。capture backendのfixtureはパケット取得の実証には含めない。Windowsの実capture・rotation・E1R併用は、Wireshark／Npcap導入後の検証項目とする。

Linuxでは既存の実capture試験を再実行し、PCAPNG、PCAP、時間／サイズrotation、E1R同時受信・offline復号、独立停止、容量不足停止がすべて成功。追加20,000 UDPパケットの連番も全件一致し、kernel／capture dropsは0。
回帰試験の証跡: `validation-artifacts/20260916_235303/9baae44a/results.json`。

WindowsではRecorderがCtrl+C／Ctrl+Breakを受け、専用の子consoleへCTRL_BREAKを届けてdumpcapの正常終了を待つ。Task Managerや`Stop-Process`による強制終了はこの経路を通らない。実装上の根拠: [dumpcapのWindows終了処理](https://github.com/wireshark/wireshark/blob/master/dumpcap.c)、[Windows console control](https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent)。

## Linux実captureの結果

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

## 初期版（v0.1.0）の自動試験

`python -m pytest -q`: **19 passed**。

CLI排他・形式推論・不正引数、フィルタ不使用、非循環rotation、既存ファイル保護、開始前／実行中の容量不足、NIC消失、capture異常、正常／強制停止、未知drop、非ゼロdrop警告、PCAP破損、PCAPNG両endian・十進／二進timestamp分解能・ISBを検証。

独立パッケージとしてeditable install、CLI help、interface一覧の実行も成功。

## 初期版（v0.1.0）の実capture

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
- WindowsではNpcap、Linuxではlibpcapを使用する。WSLで実行する場合の観測範囲はWSLのinterfaceであり、Windows NICを直接記録する場合はWindows版Pythonから起動する。

GitHubへの転送は接続済みGitHub APIを使用。ローカルGitのCLI認証情報は新規作成・保存しない。
