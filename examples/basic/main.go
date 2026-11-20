// Command basic shows how to append to a Kolo log, prove an entry and delete it.
package main

import (
	"errors"
	"fmt"
	"log"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
)

func main() {
	me, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	l, err := kololog.New(me, kololog.NewMemory())
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for _, s := range []string{"first", "second", "third"} {
		if _, err := l.Append([]byte(s)); err != nil {
			log.Fatal(err)
		}
	}
	data, err := l.Get(1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("entries: %d, entry 1: %s\n", l.Len(), data)

	// A reader trusts the owner's public key and the log ID it expects.
	pub, logID := me.PublicKey(), l.ID()
	h, err := l.Head()
	if err != nil {
		log.Fatal(err)
	}
	head, err := kololog.VerifyHead(pub, logID, h)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("head valid: true, size", head.Size())
	rec, err := l.Record(1)
	if err != nil {
		log.Fatal(err)
	}
	proof, err := l.InclusionProof(1, head.Size())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("record 1 valid:", kololog.VerifyRecord(pub, logID, rec))
	fmt.Println("entry 1 included:", kololog.VerifyInclusion(head, rec, proof))

	// Deleting destroys the entry key; the head and the proof still hold.
	if err := l.Delete(1); err != nil {
		log.Fatal(err)
	}
	_, err = l.Get(1)
	fmt.Println("entry 1 deleted:", errors.Is(err, kololog.ErrDeleted))
	fmt.Println("still included:", kololog.VerifyInclusion(head, rec, proof))

	if _, err := l.Append([]byte("fourth")); err != nil {
		log.Fatal(err)
	}
	h, err = l.Head()
	if err != nil {
		log.Fatal(err)
	}
	newHead, err := kololog.VerifyHead(pub, logID, h)
	if err != nil {
		log.Fatal(err)
	}
	cp, err := l.ConsistencyProof(head.Size(), newHead.Size())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("consistent:", kololog.VerifyConsistency(head, newHead, cp))

	// A JSON log stores any value and reads it back into a typed variable.
	type note struct {
		Text string `json:"text"`
	}
	storage := kololog.NewMemory()
	notes, err := kololog.New(me, storage, kololog.WithValueEncoding(kololog.JSON))
	if err != nil {
		log.Fatal(err)
	}
	i, err := notes.Append(note{Text: "hello kolo"})
	if err != nil {
		log.Fatal(err)
	}
	var n note
	if err := notes.Read(i, &n); err != nil {
		log.Fatal(err)
	}
	fmt.Println("note:", n.Text)

	// A storage layer keeps the signed header and the latest head; Restore verifies them and every stored entry.
	header := notes.Header()
	fmt.Println("header:", header)
	nh, err := notes.Head()
	if err != nil {
		log.Fatal(err)
	}
	notes.Close()
	reopened, err := kololog.Restore(me, header.Encode(), nh.Encode(), storage, kololog.WithValueEncoding(kololog.JSON))
	if err != nil {
		log.Fatal(err)
	}
	defer reopened.Close()
	var again note
	if err := reopened.Read(i, &again); err != nil {
		log.Fatal(err)
	}
	fmt.Println("same log ID:", reopened.ID() == notes.ID(), "restored note:", again.Text)
}
