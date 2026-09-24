//go:build !linux

package main

// Stubs so the package still builds for other systems (the router is Linux-only).

import "errors"

func monNeighDump() ([]monNeigh, error) { return nil, errors.New("neighbour table: Linux only") }

func monReadKlog() (string, error) { return "", errors.New("kernel log: Linux only") }
