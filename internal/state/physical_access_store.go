package state

import "context"

func (s *Store) PhysicalAccessEnrollments(ctx context.Context) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id LIKE 'access_%' ORDER BY fact_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][]byte
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		result = append(result, raw)
	}
	return result, rows.Err()
}
