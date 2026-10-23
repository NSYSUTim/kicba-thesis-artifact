"""Standalone scientific plot from per-boot retained cost distributions."""
import json
import os
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'phase1/.render_deps'))
os.environ.setdefault('MPLCONFIGDIR',str(ROOT/'phase1/.mpl_cache'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import numpy as np

folder=ROOT/'phase2/analysis'
data=json.loads((folder/'summary.json').read_text())
font=FontProperties(fname='C:/Windows/Fonts/msjh.ttc')
fig,axes=plt.subplots(1,2,figsize=(12,4.7),sharey=True,layout='constrained')
for axis,tag in zip(axes,('kernel68','kernel65')):
    boots=[b for b in data['boots'] if b['environment_tag']==tag]
    positions=np.arange(len(boots))
    for offset,(implementation,label,color) in enumerate((('parse','僅解析','#9CA3AF'),
                                                         ('legacy','原診斷完整量測','#5865A8'),
                                                         ('packed','合併完整量測','#168B87'))):
        groups=[b['cost']['groups']['65536/baseline/'+implementation]['wall_ns'] for b in boots]
        values=np.array([g['median']/1e6 for g in groups])
        error=np.array([[g['median']/1e6-g['q1']/1e6 for g in groups],
                        [g['q3']/1e6-g['median']/1e6 for g in groups]])
        axis.bar(positions+(offset-1)*.24,values,.22,label=label,color=color,yerr=error,capsize=3)
        for x,y,high in zip(positions+(offset-1)*.24,values,(g['q3']/1e6 for g in groups)):
            axis.text(x,max(y,high)+4,f'{y:.1f}',ha='center',fontsize=9)
    axis.set_xticks(positions,[f'開機 {b["boot_index"]}' for b in boots],fontproperties=font)
    axis.set_title(boots[0]['kernel'],fontsize=12)
    axis.set_ylim(0,245)
    axis.grid(axis='y',alpha=.2);axis.set_axisbelow(True)
    axis.spines[['top','right']].set_visible(False)
axes[0].set_ylabel('端到端時間（ms）',fontproperties=font)
axes[0].legend(prop=font,loc='upper left',frameon=False)
fig.suptitle('65,536 項、無額外負載：保留同次指紋與 IBLT 的完整量測',fontproperties=font,fontsize=15)
fig.supxlabel('各柱為每次開機 10 個主要樣本的中位數；誤差棒為四分位距',fontproperties=font,fontsize=10)
fig.savefig(folder/'cost_comparison.png',dpi=180)
plt.close(fig)
print('plot',str(folder/'cost_comparison.png'))
