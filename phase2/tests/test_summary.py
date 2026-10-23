import unittest
try:
    from phase2.summary import quality_summary, paired_costs
except ImportError:
    quality_summary=paired_costs=None


class SummaryTests(unittest.TestCase):
    def setUp(self): self.assertIsNotNone(quality_summary,'summary module not implemented')

    def test_invalid_and_unexercised_are_reported_separately(self):
        common={'kind':'static','implementation':'packed','output_match':True,
                'expected_difference':False,'recovery_match':True,'verdict_match':True,
                'mutation_exercised':True,'verdict':'equal','decode_success':True}
        rows=[common,{**common,'verdict':'invalid','verdict_match':False},
              {**common,'mutation_exercised':False}]
        result=quality_summary(rows)
        self.assertEqual(result['static_measured'],3)
        self.assertEqual(result['invalid'],1)
        self.assertEqual(result['not_exercised'],1)
        self.assertEqual(result['wrong_valid_verdict'],0)

    def test_wrong_success_not_hidden_by_equal_counts(self):
        result=quality_summary([{'kind':'static','implementation':'packed','verdict':'different',
            'output_match':True,'expected_difference':True,'verdict_match':True,
            'recovery_match':False,'decode_success':True,'mutation_exercised':True}])
        self.assertEqual(result['incorrect_decode_success'],1)

    def test_warmup_and_invalid_pairs_do_not_enter_speed_ratio(self):
        common={'kind':'cost','cardinality':65536,'condition':'baseline','warmup':False,
                'count_match':True,'load_active':True,'verdict':'equal','decode_success':True}
        rows=[{**common,'block':0,'implementation':'legacy','wall_ns':100},
              {**common,'block':0,'implementation':'packed','wall_ns':60},
              {**common,'block':1,'implementation':'legacy','wall_ns':100},
              {**common,'block':1,'implementation':'packed','wall_ns':1,'verdict':'invalid'},
              {**common,'block':-1,'implementation':'legacy','wall_ns':100,'warmup':True},
              {**common,'block':-1,'implementation':'packed','wall_ns':1,'warmup':True}]
        result=paired_costs(rows)['65536/baseline']
        self.assertEqual(result['paired_blocks'],1)
        self.assertEqual(result['candidate_over_legacy']['median'],0.6)
        self.assertEqual(result['incomplete_or_invalid_blocks'],1)


if __name__=='__main__':unittest.main()
