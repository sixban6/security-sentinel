package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"

	"github.com/egoist/mygo/ui"
)

var (
	IconShield = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`))
	IconGrid   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg>`))
	IconServer = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`))
	IconBug    = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>`))
	IconSync   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>`))
	IconClock  = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>`))
	IconKey    = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/></svg>`))
	IconTerm   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`))
	IconBolt   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/></svg>`))
	IconSpark  = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/></svg>`))
	IconPlus   = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="M12 5v14"/></svg>`))
	IconFolder = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg>`))
	IconRadar  = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/></svg>`))
)

// RenderShieldPNG draws a crisp anti-aliased shield icon for the Menu Bar Tray or App Bundle.
// posture: "clean" (emerald), "warn" (amber), "danger" (crimson), or template monochrome on macOS when clean.
func RenderShieldPNG(size int, posture string, monochromeTemplate bool) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	var primary color.NRGBA
	switch posture {
	case "danger":
		primary = color.NRGBA{R: 239, G: 68, B: 68, A: 255}
	case "warn":
		primary = color.NRGBA{R: 245, G: 158, B: 11, A: 255}
	default:
		primary = color.NRGBA{R: 16, G: 185, B: 129, A: 255}
	}
	if monochromeTemplate {
		primary = color.NRGBA{R: 0, G: 0, B: 0, A: 255}
	}

	s := float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			nx := (float64(x)+0.5)/s*2.0 - 1.0 // -1..1
			ny := (float64(y)+0.5)/s*2.0 - 1.0 // -1..1

			// Classic heraldic shield SDF approximation
			if ny < -0.78 || ny > 0.84 {
				continue
			}
			halfW := 0.72
			if ny > -0.1 {
				t := (ny + 0.1) / 0.94
				halfW = 0.72 * (1.0 - 0.88*t*t)
			} else {
				// gently arched top shoulders
				crest := 0.08 * math.Cos(nx*math.Pi*1.1)
				if ny < -0.70-crest {
					continue
				}
			}
			distEdge := halfW - math.Abs(nx)
			if distEdge <= 0 {
				continue
			}

			// Anti-aliased outer edge
			alpha := math.Min(1.0, distEdge*(s*0.35))

			if monochromeTemplate {
				// Hollow shield outline + inner checkmark/exclamation cutout for crisp macOS menu bar template
				isBorder := distEdge < 0.16 || ny < -0.58
				inGlyph := isCenterGlyph(nx, ny, posture)
				if isBorder || inGlyph {
					img.SetNRGBA(x, y, color.NRGBA{R: 0, G: 0, B: 0, A: uint8(255 * alpha)})
				}
				continue
			}

			// Rich colored shield with white inner glyph
			if isCenterGlyph(nx, ny, posture) {
				img.SetNRGBA(x, y, color.NRGBA{R: 255, G: 255, B: 255, A: uint8(255 * alpha)})
			} else {
				img.SetNRGBA(x, y, color.NRGBA{
					R: primary.R,
					G: primary.G,
					B: primary.B,
					A: uint8(float64(primary.A) * alpha),
				})
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func isCenterGlyph(nx, ny float64, posture string) bool {
	if posture == "danger" || posture == "warn" {
		// Exclamation mark '!'
		if math.Abs(nx) < 0.085 && ny > -0.36 && ny < 0.14 {
			return true
		}
		if math.Abs(nx) < 0.095 && math.Abs(ny-0.34) < 0.09 {
			return true
		}
		return false
	}
	// Checkmark '✓'
	// Segment 1: (-0.28, 0.02) -> (-0.06, 0.24)
	if distToSegment(nx, ny, -0.28, 0.02, -0.06, 0.24) < 0.085 {
		return true
	}
	// Segment 2: (-0.06, 0.24) -> (0.32, -0.20)
	if distToSegment(nx, ny, -0.06, 0.24, 0.32, -0.20) < 0.085 {
		return true
	}
	return false
}

func distToSegment(px, py, ax, ay, bx, by float64) float64 {
	vx, vy := bx-ax, by-ay
	wx, wy := px-ax, py-ay
	c1 := wx*vx + wy*vy
	if c1 <= 0 {
		return math.Hypot(px-ax, py-ay)
	}
	c2 := vx*vx + vy*vy
	if c2 <= c1 {
		return math.Hypot(px-bx, py-by)
	}
	b := c1 / c2
	pbx, pby := ax+b*vx, ay+b*vy
	return math.Hypot(px-pbx, py-pby)
}

// RenderAppBundleIconPNG generates a 1024x1024 squircle macOS/Desktop app icon with deep obsidian gradient & emerald shield.
func RenderAppBundleIconPNG(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			nx := (float64(x)+0.5)/s*2.0 - 1.0
			ny := (float64(y)+0.5)/s*2.0 - 1.0

			// Superellipse squircle background (|x/r|^5 + |y/r|^5 <= 1, r = 0.88)
			ax := math.Abs(nx) / 0.88
			ay := math.Abs(ny) / 0.88
			sq := math.Pow(ax, 5) + math.Pow(ay, 5)
			if sq > 1.02 {
				continue
			}
			bgAlpha := math.Min(1.0, (1.02-sq)*35.0)

			// Deep midnight gradient (#0f172a -> #1e293b)
			grad := (ny + 1.0) * 0.5
			rBg := uint8(13 + 15*(1.0-grad))
			gBg := uint8(20 + 22*(1.0-grad))
			bBg := uint8(38 + 35*(1.0-grad))

			// Inner heraldic shield scaled to 0.68
			sx, sy := nx/0.68, ny/0.68
			inShield := false
			shieldEdge := 0.0
			if sy >= -0.78 && sy <= 0.84 {
				halfW := 0.72
				validTop := true
				if sy > -0.1 {
					t := (sy + 0.1) / 0.94
					halfW = 0.72 * (1.0 - 0.88*t*t)
				} else {
					crest := 0.08 * math.Cos(sx*math.Pi*1.1)
					if sy < -0.70-crest {
						validTop = false
					}
				}
				if validTop {
					shieldEdge = halfW - math.Abs(sx)
					if shieldEdge > 0 {
						inShield = true
					}
				}
			}

			if inShield {
				if isCenterGlyph(sx, sy, "clean") {
					img.SetNRGBA(x, y, color.NRGBA{R: 255, G: 255, B: 255, A: uint8(255 * bgAlpha)})
				} else {
					// Vivid emerald-to-teal gradient (#10b981 -> #059669)
					shGrad := (sy + 0.8) / 1.65
					sr := uint8(16 - 8*shGrad)
					sg := uint8(195 - 40*shGrad)
					sb := uint8(140 - 30*shGrad)
					img.SetNRGBA(x, y, color.NRGBA{R: sr, G: sg, B: sb, A: uint8(255 * bgAlpha)})
				}
			} else {
				img.SetNRGBA(x, y, color.NRGBA{R: rBg, G: gBg, B: bBg, A: uint8(255 * bgAlpha)})
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
