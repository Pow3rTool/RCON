package main

import "time"

// Shared by SendInput and the advisory pointer renderer. It is an attribution
// marker, not an authentication boundary.
const desktopInputTag = uintptr(0x52434f4e)

const (
	desktopPointerLifetime      = 1800 * time.Millisecond
	desktopPointerTrailLifetime = 350 * time.Millisecond
	desktopPointerPulseLifetime = 450 * time.Millisecond
)

type desktopPointerPoint struct {
	X, Y int32 // physical virtual-desktop coordinates, including negative origins
	At   time.Time
}

// Fixed-size history bounds both hook work and paint work. No input is stored
// on disk. The Windows owner serializes access between its hook and UI threads.
type desktopPointerState struct {
	Point      desktopPointerPoint
	Buttons    uint8 // left=1, right=2, middle=4
	Trail      [24]desktopPointerPoint
	TrailCount int
	Pulses     [6]desktopPointerPoint
	PulseCount int
}

func (p *desktopPointerState) feed(message, flags uint32, extra uintptr, x, y int32, now time.Time) bool {
	if flags&1 == 0 || extra != desktopInputTag {
		return false
	}
	var down, up uint8
	switch message {
	case 0x200, 0x20a, 0x20e: // move, vertical/horizontal wheel
	case 0x201:
		down = 1
	case 0x202:
		up = 1
	case 0x204:
		down = 2
	case 0x205:
		up = 2
	case 0x207:
		down = 4
	case 0x208:
		up = 4
	default:
		return false
	}
	if p.Buttons == 0 && now.Sub(p.Point.At) >= desktopPointerLifetime {
		*p = desktopPointerState{}
	}
	point := desktopPointerPoint{x, y, now}
	if message == 0x200 && (p.Point.At.IsZero() || x != p.Point.X || y != p.Point.Y) {
		if p.TrailCount == len(p.Trail) {
			copy(p.Trail[:], p.Trail[1:])
			p.TrailCount--
		}
		p.Trail[p.TrailCount] = point
		p.TrailCount++
	}
	if down != 0 {
		if p.PulseCount == len(p.Pulses) {
			copy(p.Pulses[:], p.Pulses[1:])
			p.PulseCount--
		}
		p.Pulses[p.PulseCount] = point
		p.PulseCount++
	}
	p.Point = point
	p.Buttons = (p.Buttons | down) &^ up
	return true
}

func (p desktopPointerState) visible(now time.Time) bool {
	return !p.Point.At.IsZero() && (p.Buttons != 0 || now.Sub(p.Point.At) < desktopPointerLifetime)
}

func (p desktopPointerState) strength(now time.Time) float64 {
	if !p.visible(now) {
		return 0
	}
	if p.Buttons != 0 {
		return 1
	}
	age := now.Sub(p.Point.At)
	if age <= 600*time.Millisecond {
		return 1
	}
	return float64(desktopPointerLifetime-age) / float64(desktopPointerLifetime-600*time.Millisecond)
}
