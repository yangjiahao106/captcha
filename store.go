// Copyright 2011 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package captcha

import (
	"sync"
	"time"
)

// An object implementing Store interface can be registered with SetCustomStore
// function to handle storage and retrieval of captcha ids and solutions for
// them, replacing the default memory store.
//
// It is the responsibility of an object to delete expired and used captchas
// when necessary (for example, the default memory store collects them in Set
// method after the certain amount of captchas has been stored.)
type Store interface {
	// Set sets the digits for the captcha id.
	Set(id string, digits []byte)

	// Get returns stored digits for the captcha id. Clear indicates
	// whether the captcha must be deleted from the store.
	Get(id string, clear bool) (digits []byte)
}

// expValue stores timestamp and id of captchas. It is used in the list inside
// memoryStore for indexing generated captchas by timestamp to enable garbage
// collection of expired captchas.

// memoryStore is an internal store for captcha ids and their values.
type memoryStore struct {
	sync.RWMutex
	digitsById map[string][]byte
	timeById map[string]int64
	// Number of items stored since last collection.
	numStored int
	// Number of saved items that triggers collection.
	collectNum int
	// Expiration time of captchas.
	expiration int64
}

// NewMemoryStore returns a new standard memory store for captchas with the
// given collection threshold and expiration time (duration). The returned
// store must be registered with SetCustomStore to replace the default one.
func NewMemoryStore(collectNum int, expiration int64) Store {
	s := new(memoryStore)
	s.digitsById = make(map[string][]byte)
	s.timeById = make(map[string]int64)
	s.collectNum = collectNum
	s.expiration = expiration
	return s
}

func (s *memoryStore) Set(id string, digits []byte) {
	s.Lock()
	s.digitsById[id] = digits
	s.timeById[id] = time.Now().Unix()
	s.numStored++
	if s.numStored <= s.collectNum {
		s.Unlock()
		return
	}
	s.Unlock()
	go s.collect()
}

func (s *memoryStore) Get(id string, clear bool) (digits []byte) {
	if !clear {
		// When we don't need to clear captcha, acquire read lock.
		s.RLock()
		defer s.RUnlock()
	} else {
		s.Lock()
		defer s.Unlock()
	}

	digits, ok := s.digitsById[id]
	if !ok {
		return
	}
	t, ok := s.timeById[id]
	if !ok {
		return []byte{}
	} else {
		if t+s.expiration < time.Now().Unix() {
			delete(s.digitsById, id)
			delete(s.timeById, id)
			return []byte{}
		}
	}

	if clear {
		delete(s.digitsById, id)
		delete(s.timeById, id)

		// XXX(dchest) Index (s.timeById) will be cleaned when
		// collecting expired captchas.  Can't clean it here, because
		// we don't store reference to expValue in the map.
		// Maybe store it?
	}
	return
}

// garbage collection
func (s *memoryStore) collect() {
	now := time.Now().Unix()
	s.Lock()
	defer s.Unlock()
	s.numStored = 0

	for k, v := range s.timeById {
		if v+s.expiration < now {
			delete(s.digitsById, k)
			delete(s.timeById, k)
		}
	}
}
