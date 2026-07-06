## 翻譯

- [簡體中文（Simplified Chinese）](README_zh.md)
- [繁體中文（Traditional Chinese）](README_zh_TW.md)

## 維護模式

這個專案處於維護模式。我們仍會留意此專案，其中的程式碼也仍可正常使用，但可能會有很長一段時間看不到新的 commit。我們仍會透過 issues 接受功能請求與錯誤回報。

## OME/OME-M 與外掛程式 API 範例／Cookbook

這個專案提供 OME/OME-M API 的完整使用範例。我們將這些指令碼設計為可獨立使用，但它們也適合用在其他人的指令碼中。

指令碼分為 Python 與 PowerShell。雖然我們盡力維持兩者功能一致，但有時仍會有所差異。這些差異通常會在 [說明文件](../API.md) 中註明。

## 所有指令碼的完整清單

請參閱 [說明文件](../API.md)。OME 指令碼會依功能類型列出；若指令碼屬於外掛程式，則會依外掛程式列出。

## PowerShell 指令碼需要 PS7

為了讓此專案更能因應未來需求，並讓程式碼可在多個平台之間移植，所有新增到此專案的指令碼都會針對 PowerShell（Core）7 撰寫。Microsoft 在 [GitHub 頁面](https://github.com/PowerShell/PowerShell/releases) 提供 PowerShell 7。

部分較舊的指令碼可能沒有這項需求。可以檢視指令碼最上方來判斷是否需要 PowerShell 7。若第一行是 `#Requires -Version 7`，表示該指令碼需要 PowerShell 7。

### PS5.1 支援

我們目前沒有任何將新指令碼回溯移植或提供跨版本相容性的計畫。如果社群有足夠興趣，我們會提高優先順序。如果 PS5.1 對您而言是硬性需求，請在 [這張 ticket](https://github.com/dell/OpenManage-Enterprise/issues/181) 留言。

## 歡迎提供意見

我們大多會根據使用者意見建立、修訂或新增指令碼功能。如果有您想看到的內容，而且適用於廣泛受眾，請在 [我們的 issues 頁面](https://github.com/dell/OpenManage-Enterprise/issues) 建立 issue，或在既有 issue 中留言。這對判斷社群需要哪些功能非常有幫助。

## 指令碼說明文件

如需每個指令碼及其對應說明文件的清單，請參閱我們的 [範例 API 說明文件](../API.md)。

## 撰寫自己的程式碼

所有指令碼都是獨立完整的。我們刻意不使用內部程式庫。若要撰寫自己的程式碼，只要複製其中一個指令碼，並依照需求修改即可。我們在下列連結提供常見工作的樣板程式碼：

[Python 常用程式碼](../python_library_code.md)
<br>
[PowerShell 常用程式碼](../powershell_library_code.md)

## 為此專案貢獻

如需更多為此專案貢獻的相關資訊，請參閱 [貢獻指南](../CONTRIBUTING.md)。

## devel 分支

devel 分支包含未經測試的指令碼，或尚未符合貢獻者指南的指令碼。如果在 master 分支找不到需要的內容，而且願意協助測試，可以到 devel 分支找找看。

如果您有自己製作且認為可能有幫助的指令碼，但沒有時間整理到符合貢獻者指南，也歡迎對 devel 分支提出 pull request。

## 問題

如果使用指令碼時遇到問題，可以在 [我們的 issues](https://github.com/dell/OpenManage-Enterprise/issues) 發文。如果可以，請提供導致問題的確切命令、重現問題所需的任何 OME 設定，或是如果已經發現是程式碼問題，請清楚描述問題所在。

## 作者

* **Raajeev Kalyanaraman**
* **Vittal Reddy**
* **Laxmi Joshi**
* **Trevor Squillario**
* **Prasad Rao**
* **Grant Curell**

### Power Manager 外掛程式作者

* **Mahendran Panneerselvam**
* **Ashish Singh**
* **Rishi Mukherjee**

## 目前維護者

Grant Curell

如果有任何問題不屬於功能請求或問題回報類別，歡迎透過 grant_curell(at)dell(dot)com 聯絡。

## 授權

Copyright (c) 2026 Dell EMC Corporation
