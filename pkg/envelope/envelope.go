package envelope

const (
	V1 = ""
)

type Recipient struct {
	PubKey  string
	EPubKey string
	DocKey  []byte
}

type Envelope struct {
	Version    string
	Recipients []*Recipient
	Body       []byte
}

func NewEnvelope(version string, recipients []*Recipient, body []byte) *Envelope {
	return &Envelope{
		Version:    version,
		Recipients: recipients,
		Body:       body,
	}
}
