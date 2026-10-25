package store

import (
	"errors"
	"fmt"

	"github.com/carsonzuniga/tinyvault/internal/formats"
)

var ErrBadReference = errors.New("cannot resolve references")

func (s *Store) Export(project, env, format string, resolve bool, actor, detail string) (string, error) {
	m, err := s.getAll(project, env)
	if err != nil {
		return "", err
	}
	if resolve {
		if m, err = formats.Resolve(m); err != nil {
			return "", fmt.Errorf("%w: %v", ErrBadReference, err)
		}
	}
	out, err := formats.Render(format, project+"-"+env, m)
	if err != nil {
		return "", err
	}
	if err := s.Audit(actor, "secret.export", project+"/"+env, detail); err != nil {
		return "", err
	}
	return out, nil
}
