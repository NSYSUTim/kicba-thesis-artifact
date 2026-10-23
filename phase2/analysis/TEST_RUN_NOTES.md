# 最終本機測試紀錄

最初嘗試 `unittest.discover('phase1/tests', top_level_dir='.')`，因該既有測試目錄沒有套件初始化檔，載入即回報 `Start directory is not importable`，沒有執行任何測試。未修改既有目錄或測試，改用 `phase1.tests.<module>` 名稱載入，再加第二階段純 Python 與原專案測試。

修正呼叫後：55 項中實際執行 43 項，全部通過，失敗及錯誤為 0；12 項依既有條件在 Windows 跳過。數字見 [PYTHON_TESTS.json](PYTHON_TESTS.json)。跳過不算成核心測試通過，Linux 原生測試另以兩環境的結果及原始故障資料支持。

第二階段純 Python 測試可用 `python -m unittest phase2.tests.test_oracle phase2.tests.test_summary -v` 重跑；第一階段可用 `python -m unittest discover -s phase1/tests -v`，原專案測試需讓 `src/` 位於 Python 搜尋路徑。
