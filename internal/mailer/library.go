package mailer

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/store"
)

// LibraryStore persists template overrides.
type LibraryStore interface {
	ListEmailTemplates(ctx context.Context) ([]store.EmailTemplateRow, error)
	SaveEmailTemplate(ctx context.Context, r store.EmailTemplateRow) error
	DeleteEmailTemplate(ctx context.Context, name, locale string) error
}

type override struct {
	src       Source
	updatedAt time.Time
}

// Library holds the templates saved in the admin UI. It implements Overrides
// and reloads periodically so every replica sends the same emails.
type Library struct {
	store    LibraryStore
	renderer *Renderer
	log      *slog.Logger
	cur      atomic.Pointer[map[string]override]
}

// NewLibrary attaches itself to renderer as its override source.
func NewLibrary(st LibraryStore, renderer *Renderer, log *slog.Logger) *Library {
	l := &Library{store: st, renderer: renderer, log: log}
	empty := map[string]override{}
	l.cur.Store(&empty)
	renderer.WithOverrides(l)
	return l
}

func key(name, locale string) string { return name + "/" + locale }

// Override implements Overrides.
func (l *Library) Override(name, locale string) (Source, bool) {
	o, ok := (*l.cur.Load())[key(name, locale)]
	return o.src, ok
}

// UpdatedAt reports when a template was last saved (zero if built-in).
func (l *Library) UpdatedAt(name, locale string) time.Time {
	return (*l.cur.Load())[key(name, locale)].updatedAt
}

// Reload reads every override from the database.
func (l *Library) Reload(ctx context.Context) error {
	rows, err := l.store.ListEmailTemplates(ctx)
	if err != nil {
		return err
	}
	m := map[string]override{}
	for _, r := range rows {
		m[key(r.Name, r.Locale)] = override{src: Source{Subject: r.Subject, HTML: r.HTML, Text: r.Text}, updatedAt: r.UpdatedAt}
	}
	l.cur.Store(&m)
	return nil
}

// Run reloads until ctx is cancelled.
func (l *Library) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.Reload(ctx); err != nil && ctx.Err() == nil {
				l.log.Error("email templates reload failed", "err", err)
			}
		}
	}
}

// Preview renders src for name with sample data. For the layout, the first
// template is rendered inside it.
func (l *Library) Preview(name, locale string, src Source) (Message, error) {
	if name == LayoutName {
		body, _ := l.renderer.Effective(Templates[0].Name, locale)
		return l.renderer.RenderSource("preview@example.com", body, src.HTML, SampleFor(&Templates[0], l.renderer.Locale(locale)))
	}
	info := Lookup(name)
	if info == nil {
		return Message{}, domain.ErrNotFound
	}
	layout, _ := l.renderer.Effective(LayoutName, locale)
	return l.renderer.RenderSource("preview@example.com", src, layout.HTML, SampleFor(info, l.renderer.Locale(locale)))
}

// Save validates and stores a template override for one language.
func (l *Library) Save(ctx context.Context, name, locale string, src Source) error {
	if !i18n.Supported(locale) {
		return domain.ErrValidation.WithMessage("Unsupported language.")
	}
	src.Subject = strings.TrimSpace(src.Subject)
	if len(src.Subject) > 300 || len(src.HTML) > 100<<10 || len(src.Text) > 50<<10 {
		return domain.ErrValidation.WithMessage("Template too large (subject 300 bytes, HTML 100 KiB, text 50 KiB).")
	}
	if name == LayoutName {
		if !strings.Contains(src.HTML, `define "layout_start"`) || !strings.Contains(src.HTML, `define "layout_end"`) {
			return domain.ErrValidation.WithMessage(`The layout must define "layout_start" and "layout_end".`)
		}
		// Every template must still render inside the new layout.
		for _, t := range Templates {
			body, _ := l.renderer.Effective(t.Name, locale)
			if _, err := l.renderer.RenderSource("check@example.com", body, src.HTML, t.Sample); err != nil {
				return domain.ErrValidation.WithMessage(t.Title + " no longer renders: " + err.Error())
			}
		}
	} else {
		if strings.TrimSpace(src.Text) == "" || strings.TrimSpace(src.HTML) == "" {
			return domain.ErrValidation.WithMessage("Both the HTML and the plain text version are required.")
		}
		if _, err := l.Preview(name, locale, src); err != nil {
			if de := domain.AsError(err); de != nil {
				return err
			}
			return domain.ErrValidation.WithMessage(err.Error())
		}
	}
	if err := l.store.SaveEmailTemplate(ctx, store.EmailTemplateRow{Name: name, Locale: locale, Subject: src.Subject, HTML: src.HTML, Text: src.Text}); err != nil {
		return err
	}
	return l.Reload(ctx)
}

// Reset removes an override; the built-in template applies again.
func (l *Library) Reset(ctx context.Context, name, locale string) error {
	if err := l.store.DeleteEmailTemplate(ctx, name, locale); err != nil {
		return err
	}
	return l.Reload(ctx)
}
