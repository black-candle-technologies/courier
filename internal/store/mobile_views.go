package store

import "database/sql"

// MobileMessages is a read projection of the plaintext messages the user's
// agent already opted to mirror to the dashboard. It cannot decrypt relay data.
// Every query includes the linked dashboard owner and live expiry predicate.
func (s *Store) MobileMessages(userID, before int64, query string, bridgedOnly bool, limit int) ([]DashboardMessage, error) {
	if limit < 1 || limit > 51 {
		limit = 26
	}
	rows, err := s.db.Query(`SELECT id,courier_id,sender,recipient,body,sent_at,received_at,reply_to,quote,expires_at,bridged
	 FROM dashboard_messages WHERE user_id=? AND `+liveMessageExpr("")+`
	 AND (?=0 OR id<?) AND instr(lower(body),lower(?))>0 AND (?=0 OR bridged=1)
	 ORDER BY id DESC LIMIT ?`, userID, before, before, query, bridgedOnly, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DashboardMessage{}
	for rows.Next() {
		var m DashboardMessage
		var b int
		if err = rows.Scan(&m.ID, &m.CourierID, &m.Sender, &m.Recipient, &m.Body, &m.SentAt, &m.ReceivedAt, &m.ReplyTo, &m.Quote, &m.ExpiresAt, &b); err != nil {
			return nil, err
		}
		m.Bridged = b != 0
		result = append(result, m)
	}
	return result, rows.Err()
}
func (s *Store) MobileMessage(userID, id int64) (*DashboardMessage, error) {
	var m DashboardMessage
	var b int
	err := s.db.QueryRow(`SELECT id,courier_id,sender,recipient,body,sent_at,received_at,reply_to,quote,expires_at,bridged
	 FROM dashboard_messages WHERE user_id=? AND id=? AND `+liveMessageExpr(""), userID, id).Scan(&m.ID, &m.CourierID, &m.Sender, &m.Recipient, &m.Body, &m.SentAt, &m.ReceivedAt, &m.ReplyTo, &m.Quote, &m.ExpiresAt, &b)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	m.Bridged = b != 0
	return &m, err
}
func (s *Store) MobileMessageCount(userID int64) (int64, error) {
	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM dashboard_messages WHERE user_id=? AND `+liveMessageExpr(""), userID).Scan(&count)
	return count, err
}
