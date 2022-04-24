# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = /root/nff-go/mk
IMAGENAME = VoIP-Analyzer-main
EXECUTABLES = VoIP-Analyzer

export GO_BUILD_TAGS += -tags hyperscan_v4
gohs:
	go get -tags hyperscan_v4 -v github.com/flier/gohs/hyperscan

include $(PATH_TO_MK)/leaf.mk
