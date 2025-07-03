package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func NotifyWebhook(uid, oldIP, newIP string) error {
	payload := map[string]any{
		"user_id": uid,
		"old_ip":  oldIP,
		"new_ip":  newIP,
		"time":    time.Now().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post("https://webhook.com/alert", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode%100 != 2 {
		return fmt.Errorf("webhook failed with status %d", resp.StatusCode)
	}
	return nil
}
