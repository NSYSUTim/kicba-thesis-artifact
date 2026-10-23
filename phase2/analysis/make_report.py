"""Regenerate derived phase-two analysis from retained raw evidence."""
import ast
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.summary import summarize
from phase2.oracle import identities,difference,token_rows,SEED1,SEED2
from phase2.run_campaign import expected_output
from kicba.reconciliation import EntryToken,IBLT,MultisetFingerprint

PHASE=ROOT/'phase2';OUT=PHASE/'analysis'


def dump(path,data): path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')


def verify_base():
    lock=json.loads((PHASE/'LOCK.json').read_text())
    expected=lock['original_and_phase1_sha256'];mismatch=[]
    for name,digest in expected.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:mismatch.append(name)
    original=json.loads((ROOT/'phase1/LOCK.json').read_text())['original_tracked_sha256']
    published=ROOT.parent/'kicba-thesis-artifact'
    published_mismatch=[n for n,h in original.items() if hashlib.sha256((published/n).read_bytes()).hexdigest()!=h]
    clean=not subprocess.check_output(['git','status','--porcelain'],cwd=published).strip()
    record={'base_and_phase1_files':len(expected),'mismatch':mismatch,
            'published_original_files':len(original),'published_mismatch':published_mismatch,'published_clean':clean}
    if mismatch or published_mismatch or not clean:raise RuntimeError('base files changed')
    return record


def audit_static(folder,rows):
    oracles={fs:json.loads((folder/('oracle_'+fs+'.json')).read_text()) for fs in ('ext4','tmpfs')}
    counts=Counter()
    for row in rows:
        if row['kind']!='static':continue
        counts['trials']+=1
        original=oracles[row['fs']]
        actual=[json.loads(s) for s in (folder/row['actual_file']).read_text().splitlines()]
        expected=expected_output(original,row['state'],row['mutation_exercised'])
        if identities(actual)!=identities(expected):counts['output_mismatch']+=1
        if row['implementation']=='parse':continue
        up,down=difference(original,actual)
        if row['verdict'] not in ('equal','different'):counts['invalid']+=1;continue
        if (row['verdict']=='different')!=bool(up or down):counts['wrong_verdict']+=1
        if row.get('decode_success'):
            if sorted(row['upstream_only'])!=up or sorted(row['downstream_only'])!=down:
                counts['incorrect_success']+=1
        else:counts['decode_failed']+=1
    return dict(counts)


def audit_dynamic(folder,rows):
    counts=Counter()
    activity={fs:json.loads((folder/('churn_events_'+fs+'.json')).read_text()) for fs in ('ext4','tmpfs')}
    if any(d['errors'] or not d['worker_stopped'] for d in activity.values()):counts['worker_error']+=1
    for row in rows:
        if row['kind']!='dynamic':continue
        counts['trials']+=1
        actual=[json.loads(s) for s in (folder/row['actual_file']).read_text().splitlines()]
        tokens=[EntryToken(*r) for r in token_rows(actual)]
        fp=list(MultisetFingerprint.from_tokens(tokens).as_tuple())
        visible=row['userspace']
        start,end=visible['scan_started_ns'],visible['scan_finished_ns']
        overlap=Counter(op for timestamp,op in activity[row['fs']]['events'] if start<=timestamp<=end)
        if start>=end or dict(overlap)!=row['churn_in_scan'] or any(overlap[op]<=0 for op in ('create','rename','delete')):
            counts['activity_window_mismatch']+=1
        if fp!=[visible['count'],visible['sum1'],visible['sum2']]:counts['userspace_fingerprint_mismatch']+=1
        if row.get('kernel_fingerprint')!=fp:counts['kernel_fingerprint_mismatch']+=1
        expected=[list(r) for r in IBLT.from_tokens(tokens,256,SEED1,SEED2).to_rows()]
        if row.get('kernel_rows')!=expected:counts['kernel_cells_mismatch']+=1
        if row.get('decode_success') is not True or row.get('upstream_only')!=[] or row.get('downstream_only')!=[]:
            counts['nonempty_or_failed_decode']+=1
    return dict(counts)


def audit_native(tag,lock):
    folder=PHASE/'evidence/native_checks'/lock['kernel']/'final_attempt1'
    paths=sorted(folder.glob('*.json'))
    if len(paths)!=18:raise RuntimeError('native evidence incomplete '+tag)
    allowed={digest for name,digest in lock['source_sha256'].items() if name.startswith('phase2/tests/')}
    methods=set()
    for source in ('test_native.py','test_actions.py'):
        methods.update(n.name for n in ast.walk(ast.parse((PHASE/'tests'/source).read_text(encoding='utf-8')))
                       if isinstance(n,ast.FunctionDef) and n.name.startswith('test_'))
    covered=set()
    report={'records':len(paths),'checks':{}}
    for path in paths:
        record=json.loads(path.read_text());row=record['row'];name=path.stem
        matching=[method for method in methods if name.startswith(method+'_')]
        if len(matching)!=1:raise RuntimeError('native method cannot be identified '+name)
        covered.add(matching[0])
        if record['test_source_sha256'] not in allowed:raise RuntimeError('native test source differs '+name)
        if isinstance(row,dict) and 'actual' in row and 'expected' in row:
            if identities(row['actual'])!=identities(row['expected']):raise RuntimeError('native output differs '+name)
        if name.startswith('test_exact_accepted_'):
            m=row['measurement'];tokens=[EntryToken(*r) for r in token_rows(row['actual'])]
            if m['kernel_fingerprint']!=list(MultisetFingerprint.from_tokens(tokens).as_tuple()):raise RuntimeError('native fingerprint')
            cells=int(name.rsplit('_',1)[1])
            if m['kernel_rows']!=[list(r) for r in IBLT.from_tokens(tokens,cells,SEED1,SEED2).to_rows()]:raise RuntimeError('native cells')
            if m['verdict']!='equal' or not m['decode_success']:raise RuntimeError('native exact verdict')
        elif name.startswith('test_real_return_'):
            if len(row)!=16 or any(r['verdict']!='invalid' for r in row):raise RuntimeError('missed window not rejected')
            misses=max(v['missed_delta'] for v in row[0]['coverage']['per_event'].values())
            if misses<=0:raise RuntimeError('return loss not exercised')
            report['real_return_missed_delta']=misses
        elif name.startswith('test_16_concurrent_'):
            if len({r['pid'] for r in row})!=16 or any(r['verdict']!='equal' or not r['decode_success'] for r in row):raise RuntimeError('concurrency')
        elif name.startswith(('test_missing_state_','test_invalid_cell_','test_seed_mismatch_')):
            if row['verdict']!='invalid':raise RuntimeError('fault not rejected '+name)
        elif name.startswith('test_independent_filter_small_'):
            if row['verdict']!='different' or row['decode_success']:raise RuntimeError('small capacity not exercised')
        elif name.startswith('test_each_real_action_'):
            expected='equal' if name.endswith('_reorder') else 'different'
            if row['measurement']['verdict']!=expected or not row['measurement']['decode_success']:raise RuntimeError('action verdict '+name)
        elif name.startswith('test_small_buffers_'):
            if row['verdict']!='equal' or not row['decode_success'] or row['kernel_stats']['rejected_entries']<=0:raise RuntimeError('retry accounting')
        elif not name.startswith('test_without_probes_'):raise RuntimeError('unknown native evidence '+name)
        report['checks'][name]=True
    if covered!=methods:raise RuntimeError('native method missing evidence '+tag)
    report['test_methods']=len(covered)
    return report


def main():
    OUT.mkdir(exist_ok=True)
    integrity=verify_base();dump(OUT/'base_integrity.json',integrity)
    records=[];raw_audit={};source_verification={};native_verification={};environment_verification={}
    for tag in ('kernel68','kernel65'):
        lock=json.loads((PHASE/'locks'/(tag+'.json')).read_text())
        archive=PHASE/'evidence/downloads'/('frozen_sources_'+tag+'.tar.gz')
        meta=json.loads(archive.with_suffix(archive.suffix+'.sha256.json').read_text())
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=meta['sha256']:raise RuntimeError('source archive checksum')
        with tarfile.open(archive) as bundle:
            for name,digest in lock['source_sha256'].items():
                if hashlib.sha256(bundle.extractfile(name).read()).hexdigest()!=digest:raise RuntimeError('source archive drift '+name)
        source_verification[tag]={'source_files_verified':len(lock['source_sha256']),'source_archive_sha256':meta['sha256']}
        native_verification[tag]=audit_native(tag,lock)
        final=json.loads((PHASE/f'evidence/{tag}/final_environment.json').read_text())
        env=final['inventory']
        checks={'kernel_unchanged':env['kernel']==lock['kernel'],
                'packages_unchanged':env['package_inventory_sha256']==lock['package_inventory_sha256'],
                'sources_unchanged':not final['source_drift'],'modules_removed':not final['test_modules'],
                'tracefs_probes_removed':not final['tracefs_probes'].strip()}
        if tag=='kernel68':checks.update(final['checks'])
        if not all(checks.values()):raise RuntimeError('final environment checks '+tag)
        environment_verification[tag]=checks
        for index in (1,2,3):
            folder=PHASE/f'evidence/{tag}/confirmation_boot_{index:02d}'
            saved=json.loads((folder/'summary.json').read_text())
            rows=[json.loads(s) for s in (folder/'campaign/attempts.jsonl').read_text().splitlines()]
            derived=summarize(rows)
            if any(derived[k]!=saved[k] for k in ('quality','cost')):raise RuntimeError('summary does not match raw rows')
            if saved['completed'] is not True:raise RuntimeError('confirmation failed; retain and explain before reporting completion')
            audit=audit_static(folder/'campaign',rows)
            if any(v for k,v in audit.items() if k!='trials'):raise RuntimeError('raw output audit failed '+str(audit))
            dynamic_audit=audit_dynamic(folder/'campaign',rows)
            if any(v for k,v in dynamic_audit.items() if k!='trials'):raise RuntimeError('raw dynamic audit failed '+str(dynamic_audit))
            raw_audit[f'{tag}/{index}']={'static':audit,'dynamic':dynamic_audit}
            static=[r for r in rows if r['kind']=='static' and r['implementation']!='parse']
            saved['measured_outcomes']=dict(Counter(r['verdict'] for r in static))
            saved['exercised_difference_trials']=sum(r['mutation_exercised'] and r['expected_difference'] for r in static)
            saved['not_exercised_by_case']=dict(Counter('/'.join(str(r[k]) for k in ('fs','state','buffer','implementation'))
                                         for r in rows if r['kind']=='static' and not r['mutation_exercised']))
            memories=json.loads((folder/'campaign/map_memory.json').read_text())
            saved['map_memlock_bytes']={name:sum(int(v['fields']['memlock']) for v in maps.values()) for name,maps in memories.items()}
            saved['kernel']=lock['kernel'];records.append(saved)
    if len({r['boot_id'] for r in records})!=6:raise RuntimeError('confirmation boot IDs overlap')
    dump(OUT/'summary.json',{'boots':records,'raw_output_audit':raw_audit,'source_verification':source_verification})
    dump(OUT/'native_and_environment_verification.json',{'native_checks':native_verification,'final_environments':environment_verification})
    with (OUT/'costs.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['environment','boot','condition','implementation','count','n','wall_median_ms','wall_q1_ms','wall_q3_ms','total_with_quality_ms','registration_ms','readback_ms','decode_ms','cleanup_ms'])
        for boot in records:
            for key,g in boot['cost']['groups'].items():
                count,condition,implementation=key.split('/')
                writer.writerow([boot['environment_tag'],boot['boot_index'],condition,implementation,count,g['wall_ns']['n'],
                    *[g['wall_ns'][k]/1e6 for k in ('median','q1','q3')],
                    *[g[k]['median']/1e6 for k in ('wall_with_coverage_ns','registration_ns','readback_ns','decode_ns','cleanup_ns')]])
    with (OUT/'paired_costs.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['environment','boot','condition','count','paired_blocks','ratio_median','ratio_q1','ratio_q3','invalid_pairs'])
        for boot in records:
            for key,g in boot['cost']['paired'].items():
                count,condition=key.split('/');ratio=g['candidate_over_legacy']
                writer.writerow([boot['environment_tag'],boot['boot_index'],condition,count,g['paired_blocks'],ratio['median'],ratio['q1'],ratio['q3'],g['incomplete_or_invalid_blocks']])
    lines=['# 第二階段結果：適用證據與保留定位功能的成本改良\n',
           '本輪沿用 filldir64 與專用 C 掃描器的 getdents64 兩端，補差異動作、檔案系統、動態目錄與另一作者實作，並驗證合併核心儲存的候選。沒有進入一般程序監控、/proc 或暫緩的第 4、5 項。\n',
           '## 哪些問題已經有答案\n',
           '| 問題 | 本輪能支持的結論 |\n|---|---|',
           '| 只變名稱以外欄位或新增項目是否有效？ | 已實測新增、變長／變短改名、inode-only、type-only、移除；有效且實際變更時須依身分差異判不同，重排作一致對照。 |',
           '| 正常目錄在列舉時變動會不會自然誤報？ | 本輪正常動態試驗在同次兩端比對下維持一致；不是不同時間快照相等的保證。 |',
           '| 是否只有單一核心／ext4 才有效？ | 增加 6.5 核心及 tmpfs 的受控證據，仍不是所有核心／FS 的保證。 |',
           '| 核心逐項處理能否降低成本？ | 保留指紋、同次 IBLT 與拒判規則，改為每程序合併狀態及 cell 儲存，以配對時間判斷收益。 |\n',
           '## 環境與確認分母\n',
           '同一 Hyper-V 主機，原 VM 為 Ubuntu 22.04.5／Linux 6.8.0-138-generic，複本為相同使用者空間加指定 Linux 6.5.0-45-generic 套件，均 4 vCPU／8 GiB。兩台交替執行，不同時使用同 IP。6.5 是較舊核心的相容性對照；複本的磁碟布局不同，不能把跨環境的時間差全歸因核心。每環境三個新開機，各自先導不混入。\n',
           '| 環境／開機 | boot ID | 量測靜態 | 無探針控制 | 動態 | 成本主要／暖機 |\n|---|---|---:|---:|---:|---:|']
    for b in records:
        q,c=b['quality'],b['cost']
        lines.append(f"| {b['environment_tag']} / {b['boot_index']} | `{b['boot_id']}` | {q['static_measured']} | {q['static_controls']} | {q['dynamic']} | {c['primary']} / {c['warmups']} |")
    totals=Counter()
    for b in records:
        for k,v in b['quality'].items():
            if isinstance(v,int):totals[k]+=v
    different=sum(b['measured_outcomes'].get('different',0) for b in records)
    equal=sum(b['measured_outcomes'].get('equal',0) for b in records)
    lines += [f"\n合計量測靜態 {totals['static_measured']:,} 次（有效不同 {different:,}、有效一致 {equal:,}、無效 {totals['invalid']}），另有無探針控制 {totals['static_controls']} 次；正常動態 {totals['dynamic']} 次。原始輸出逐筆重新核對，輸出不符、有效判讀錯誤、錯誤解碼成功皆為 0。\n",
              '## 差異動作、還原與未實際變更\n',
              f"每個核心／FS／緩衝區／量測版按同規約執行。共 {totals['not_exercised']} 次靜態試驗因小緩衝區餘量不足，注入器沒有實際新增項目（含無探針控制）；本輪此類未變更全部發生在新增項目情境，變長改名的確認試驗均有實際變更。這些未變更對照沒有算成成功陽性。每種差異在大緩衝區均有實際變更的正例。完整分組與 skip 清單見 [summary.json](analysis/summary.json)。\n",
              '差異還原以獨立預期名稱位元組、inode、型態計算 token 多重集合核對，不以解碼輸出當答案。正常重排只變順序，依原設計不應警報。差異警報不判斷是否惡意。合法小容量的獨立故障檢查另保存，還原失敗時仍保留有效指紋差異；這不保證任意差異量都可解碼。\n',
              '## 動態目錄的結果如何解讀\n',
              f"{totals['dynamic']} 次測試均要求掃描起訖內實際有建立、改名與刪除；無效 {totals['dynamic_invalid']}、不同 {totals['dynamic_difference']}、未證實活動 {totals['dynamic_not_exercised']}。掃描器在每次系統呼叫後固定等待 1 ms，增加背景操作交錯機會，屬排程壓力對照。此等待版不進成本比較。這支持受測的同次交付一致性，不能由此得到目錄的原子快照或動態隱藏攻擊偵測率。\n",
              '## 另一作者實作與觀測干擾\n',
              '採 xcellerator/linux_kernel_hacking 固定提交的目錄過濾函式，驗證無探針仍能隱藏，並比較模組先載／探針先掛。相容 ftrace helper 與原研究共用，因而是另一作者過濾實作的外部證據，並非獨立掛接家族、未知 rootkit 的偵測率或完整現實攻擊覆蓋。[來源與移植說明](third_party/xcellerator/PORTING_zh-TW.md)\n',
              '## 改了什麼，以及有沒有省到主要成本\n',
              '核心仍逐項建立指紋與 IBLT，也維持最外層返回 true 才計入。原診斷版將 depth、pending、指紋、統計與 IBLT 分置多張 map；候選先為每個登記執行緒配置一筆合併狀態，將 256 個 cell 一併存入，減少逐項查表及使用者端逐表讀回、清理。這不是正常時免建 IBLT，也沒有把第一次資訊丟掉後靠重掃定位。\n',
              '兩版用同一 C binary、相同參數與隨機配對區組；總時間含程序啟動、登記、列舉、讀回、解碼、清理，另報含品質查詢的時間。編譯／附掛不在此邊界內。每格為該開機 10 次主要試驗的中位數；配對比值先逐區組計算，不是拿兩個獨立中位數硬除。\n',
              '| 核心／開機，65,536 項、無額外負載 | 解析基線 ms | 原診斷完整 ms | 合併完整 ms | 配對比值中位數 |\n|---|---:|---:|---:|---:|']
    all_recommended=True
    for b in records:
        groups=b['cost']['groups'];values=[groups['65536/baseline/'+n]['wall_ns']['median']/1e6 for n in ('parse','legacy','packed')]
        ratio=b['cost']['paired']['65536/baseline']['candidate_over_legacy']['median']
        all_recommended &= ratio<.9
        lines.append(f"| {b['kernel']} / {b['boot_index']} | {values[0]:.2f} | {values[1]:.2f} | {values[2]:.2f} | {ratio:.3f} |")
    lines += [f"\n預先指定門檻為每個開機的配對中位數比值 < 0.9 且品質沒有回退；本輪{'全部符合，可在受測範圍建議採用合併候選' if all_recommended else '未全部符合，不宣稱全面達到採用門檻'}。較小目錄、CPU 負載及 IQR／範圍均保留在 [costs.csv](analysis/costs.csv)、[paired_costs.csv](analysis/paired_costs.csv)，不只挑最大目錄的有利數字。\n",
              '這是同規約的新舊診斷版比較，沒有重新定義或覆寫原論文 4.76 倍。改善來自儲存與控制流程，非新增安全保證，也不能只歸因於雜湊／IBLT 演算法本身。\n',
              '![逐開機的完整量測成本](analysis/cost_comparison.png)\n',
              '## 資料量與配置指標\n',
              '| 環境／開機 | 原診斷 map memlock MiB | 合併 map memlock MiB |\n|---|---:|---:|']
    for b in records:
        m=b['map_memlock_bytes'];lines.append(f"| {b['environment_tag']} / {b['boot_index']} | {m['legacy']/2**20:.3f} | {m['packed']/2**20:.3f} |")
    lines += ['\n每次 256 cells 的邏輯摘要大小不變。表中是未附掛時 fdinfo 的核心 memlock 指標，不是整工具實體常駐／峰值。候選每筆預留最多 256 cells、表最多 256 執行緒；原版全域 65,536 cell 容量在每筆 256 時也是理想 256 筆，不能只看 monitored_pids 的 1024 上限就說原版完整定位可同時容納 1024 筆。候選對很小 cells 仍預留整筆，記憶體取捨要按宣告容量解讀。\n',
              '## 保存、限制與下一個決策\n',
              f"原 main 保持乾淨，原版 {integrity['published_original_files']} 檔、包含第一階段的基準 {integrity['base_and_phase1_files']} 檔逐檔 SHA-256 不變。各確認結束檢查版本與計時器，資料、失敗、無效與先導分開封存。來源鎖按兩環境分開，完整核對見 [base_integrity.json](analysis/base_integrity.json)。\n",
              '兩個核心各通過 10 個原生測試方法，各保留 18 份子案例證據；另由主機重新核對來源、判讀與故障控制。包含真實返回漏失、缺少狀態、未配對、配置與種子不符、16 程序併發及小容量失敗。原 VM 的核心、套件、更新計時器及清理狀態亦核對通過。[原生故障與結束環境核對](analysis/native_and_environment_verification.json)\n',
              '已請求額外代理審查，但因工作區額度不足沒有產生獨立審查結果；由主代理自查並以實測核對，不將其列成已通過的獨立審查。\n',
              '限制仍包含同一實體主機、兩個指定核心、ext4／tmpfs、受控差異與特定第三方範例。零錯誤觀察不是對所有輸入的保證。返回 profile 不涵蓋入口 perf 探針的全部執行漏失；同核心量測與公開種子的信任限制也沒有被這次優化解除。\n',
              '本輪到第二階段結束。若後續核定第三階段，才建立「只讓專用掃描器看到完整資料」的案例並評估觀察其他程序自己的列舉；這與本輪成本改良是不同研究問題。論文、簡報、GitHub 主分支尚未由本輪更新。\n',
              '方法與文獻依據見 [執行前規約](PROTOCOL_zh-TW.md)、[先導核對](PILOT_REVIEW_zh-TW.md)。']
    (PHASE/'REPORT_zh-TW.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({'boots':len(records),'quality_totals':dict(totals),'all_adoption_thresholds':bool(all_recommended)},ensure_ascii=False))


if __name__=='__main__':main()
