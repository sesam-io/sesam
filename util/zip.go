package util

import (
	"archive/zip"
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
)

func ZipDir(src string, matcher PathMatchFunc) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !matcher(path) {
			return nil
		}
		f, err := w.Create(path)
		if err != nil {
			return err
		}
		s, err := os.Open(path)
		if err != nil {
			return err
		}
		written, err := io.Copy(f, s)
		if err != nil {
			return err
		}
		// TODO print only if verbose
		log.Printf("Added %s (%d bytes written)\n", path, written)
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func UnzipTo(src string, dest string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			// ignore empty directories
			continue
		}
		file, err := f.Open()
		defer file.Close()
		if err != nil {
			return err
		}

		path := filepath.Join(dest, f.Name)
		err = os.MkdirAll(filepath.Dir(path), 0755)
		if err != nil {
			return err
		}
		d, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer d.Close()
		_, err = io.Copy(d, file)
		if err != nil {
			return err
		}
	}
	return nil
}
