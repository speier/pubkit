package proto

type Recipient struct {
	PubKey string
	DocKey []byte
}

type Envelope struct {
	Recipients []*Recipient
	Body       []byte
}
