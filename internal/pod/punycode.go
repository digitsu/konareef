// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// punycode.go — the RFC 3492 Punycode encoder, for one DNS label.
//
// The Public Suffix List writes internationalized suffixes in Unicode
// (for example "公司.cn"). A [network].egress entry is ASCII only: the
// schema accepts letters, digits and hyphens. So egress_breadth.go
// converts each Unicode PSL label to its ASCII form ("xn--" plus the
// Punycode of the label) before it compares a host with the list. The
// PSL already stores each label in the lowercase, NFC form that IDNA
// expects, so no other mapping is necessary.
//
// The standard library has no Punycode encoder, and golang.org/x/net is
// not a dependency of this module. This file is the encoder from RFC 3492
// section 6.3, with the bootstring parameters of section 5.
package pod

import (
	"errors"
	"strings"
)

// Bootstring parameters for Punycode (RFC 3492 section 5).
const (
	punycodeBase        = 36
	punycodeTMin        = 1
	punycodeTMax        = 26
	punycodeSkew        = 38
	punycodeDamp        = 700
	punycodeInitialBias = 72
	punycodeInitialN    = 128
)

// errPunycodeOverflow is returned when a label is too long for the
// encoder's integer arithmetic. No real DNS label reaches it.
var errPunycodeOverflow = errors.New("punycode: overflow")

// toASCIILabel returns the ASCII form of one DNS label. Input: one label,
// with no dot. Output: the label itself when it is all ASCII, else "xn--"
// followed by its Punycode encoding; an error only on overflow.
func toASCIILabel(label string) (string, error) {
	ascii := true
	for index := 0; index < len(label); index++ {
		if label[index] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return label, nil
	}
	encoded, err := punycodeEncode(label)
	if err != nil {
		return "", err
	}
	return "xn--" + encoded, nil
}

// punycodeEncode encodes a Unicode string with the Punycode algorithm of
// RFC 3492 section 6.3. Input: the string. Output: the encoded string,
// without the "xn--" prefix; an error only on overflow.
func punycodeEncode(input string) (string, error) {
	codePoints := []rune(input)
	var output strings.Builder
	for _, codePoint := range codePoints {
		if codePoint < 0x80 {
			output.WriteRune(codePoint)
		}
	}
	basicCount := output.Len()
	handled := basicCount
	if basicCount > 0 {
		output.WriteByte('-')
	}
	nextCodePoint := int32(punycodeInitialN)
	delta := int32(0)
	bias := int32(punycodeInitialBias)
	const maxInt32 = int32(^uint32(0) >> 1)
	for handled < len(codePoints) {
		// The smallest code point not yet handled.
		smallest := maxInt32
		for _, codePoint := range codePoints {
			if codePoint >= nextCodePoint && codePoint < smallest {
				smallest = codePoint
			}
		}
		if (smallest - nextCodePoint) > (maxInt32-delta)/int32(handled+1) {
			return "", errPunycodeOverflow
		}
		delta += (smallest - nextCodePoint) * int32(handled+1)
		nextCodePoint = smallest
		for _, codePoint := range codePoints {
			if codePoint < nextCodePoint {
				delta++
				if delta == maxInt32 {
					return "", errPunycodeOverflow
				}
			}
			if codePoint != nextCodePoint {
				continue
			}
			value := delta
			for step := int32(punycodeBase); ; step += punycodeBase {
				threshold := punycodeThreshold(step, bias)
				if value < threshold {
					break
				}
				digit := threshold + (value-threshold)%(punycodeBase-threshold)
				output.WriteByte(punycodeDigit(digit))
				value = (value - threshold) / (punycodeBase - threshold)
			}
			output.WriteByte(punycodeDigit(value))
			bias = punycodeAdapt(delta, int32(handled+1), handled == basicCount)
			delta = 0
			handled++
		}
		delta++
		nextCodePoint++
	}
	return output.String(), nil
}

// punycodeThreshold is t(k) of RFC 3492 section 6.3: bias-relative,
// clamped to [tmin, tmax].
func punycodeThreshold(step, bias int32) int32 {
	switch {
	case step <= bias:
		return punycodeTMin
	case step >= bias+punycodeTMax:
		return punycodeTMax
	default:
		return step - bias
	}
}

// punycodeDigit maps a digit value 0..35 to "a".."z" then "0".."9".
func punycodeDigit(digit int32) byte {
	if digit < 26 {
		return byte('a' + digit)
	}
	return byte('0' + digit - 26)
}

// punycodeAdapt is the bias adaptation function of RFC 3492 section 6.1.
// Inputs: the delta, the number of code points handled so far, and
// whether this is the first adaptation. Output: the new bias.
func punycodeAdapt(delta, numPoints int32, firstTime bool) int32 {
	if firstTime {
		delta /= punycodeDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	shifts := int32(0)
	for delta > ((punycodeBase-punycodeTMin)*punycodeTMax)/2 {
		delta /= punycodeBase - punycodeTMin
		shifts += punycodeBase
	}
	return shifts + (punycodeBase-punycodeTMin+1)*delta/(delta+punycodeSkew)
}
