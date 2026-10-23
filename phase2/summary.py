"""Separate quality denominators and within-boot paired performance ratios."""
from collections import Counter, defaultdict
import statistics


def distribution(values):
    values=sorted(values)
    if not values: return {'n':0}
    q=statistics.quantiles(values,n=4,method='inclusive') if len(values)>1 else [values[0]]*3
    return {'n':len(values),'median':statistics.median(values),'q1':q[0],'q3':q[2],
            'min':values[0],'max':values[-1]}


def quality_summary(rows):
    result=dict.fromkeys(('static_measured','static_controls','invalid','not_exercised',
             'output_mismatch','wrong_valid_verdict','incorrect_decode_success','decode_failed',
             'dynamic','dynamic_invalid','dynamic_difference','dynamic_not_exercised','case_failures'),0)
    by_group=defaultdict(Counter)
    for r in rows:
        if r['kind'] in ('case_failure','suite_failure'): result['case_failures']+=1
        if r['kind']=='static':
            measured=r['implementation']!='parse'
            result['static_measured' if measured else 'static_controls']+=1
            result['output_mismatch']+=r.get('output_match') is not True
            result['not_exercised']+=r.get('mutation_exercised') is not True
            if measured:
                valid=r.get('verdict') in ('equal','different')
                result['invalid']+=not valid
                result['wrong_valid_verdict']+=valid and r.get('verdict_match') is not True
                result['incorrect_decode_success']+=r.get('decode_success') is True and r.get('recovery_match') is not True
                result['decode_failed']+=valid and r.get('decode_success') is not True
                key='/'.join(str(r.get(k,'unspecified')) for k in ('fs','state','buffer','implementation','order'))
                by_group[key][r.get('verdict','missing')]+=1
                if r.get('mutation_exercised'):by_group[key]['exercised']+=1
        elif r['kind']=='dynamic':
            result['dynamic']+=1
            result['dynamic_invalid']+=r.get('verdict') not in ('equal','different')
            result['dynamic_difference']+=r.get('verdict')=='different'
            result['dynamic_not_exercised']+=r.get('churn_exercised') is not True
    result['static_groups']={key:dict(value) for key,value in by_group.items()}
    return result


def cost_valid(row):
    return (row.get('count_match') is True and row.get('load_active') is True
            and (row['implementation']=='parse' or (row.get('verdict')=='equal' and row.get('decode_success') is True)))


def paired_costs(rows):
    blocks=defaultdict(dict)
    for row in rows:
        if row['kind']=='cost' and row.get('warmup') is False:
            key=(row['cardinality'],row['condition'],row['block'])
            if row['implementation'] in blocks[key]: raise ValueError('duplicate paired cost mode')
            blocks[key][row['implementation']]=row
    result=defaultdict(lambda:{'ratios':[],'incomplete_or_invalid_blocks':0})
    for (size,condition,block),modes in blocks.items():
        record=result[f'{size}/{condition}']
        if (not {'legacy','packed'}<=set(modes)
                or not all(cost_valid(modes[n]) for n in ('legacy','packed'))):
            record['incomplete_or_invalid_blocks']+=1;continue
        record['ratios'].append(modes['packed']['wall_ns']/modes['legacy']['wall_ns'])
    return {key:{'paired_blocks':len(r['ratios']),'candidate_over_legacy':distribution(r['ratios']),
                 'incomplete_or_invalid_blocks':r['incomplete_or_invalid_blocks']} for key,r in result.items()}


def summarize(rows):
    costs=[r for r in rows if r['kind']=='cost']
    groups=defaultdict(list)
    for r in costs:
        if r.get('warmup') is False and cost_valid(r):
            groups[f"{r['cardinality']}/{r['condition']}/{r['implementation']}"].append(r)
    metrics=('wall_ns','wall_with_coverage_ns','registration_ns','readback_ns','decode_ns','cleanup_ns')
    return {'quality':quality_summary(rows),'cost':{'attempts':len(costs),
        'warmups':sum(r.get('warmup') is True for r in costs),
        'primary':sum(r.get('warmup') is False for r in costs),
        'invalid_primary':sum(r.get('warmup') is False and not cost_valid(r) for r in costs),
        'groups':{key:{m:distribution([r[m] for r in values]) for m in metrics} for key,values in groups.items()},
        'paired':paired_costs(rows)}}
