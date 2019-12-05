#!/bin/sh
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# Copyright (c) 2019 Tomer Eliyahu (Intel)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

scriptdir="$(cd "${0%/*}"; pwd)"
topdir="${scriptdir%/*/*/*}"

. ${topdir}/prplMesh/tools/docker/functions.sh

usage() {
    echo "usage: $(basename $0) [-hvbtp]"
    echo "  mandatory:"
    echo "      type - image type <runner/builder>"
    echo "  options:"
    echo "      -h|--help - show this help menu"
    echo "      -v|--verbose - verbosity on"
    echo "      -b|--base-image - Base OS image to use (Dockerfile 'FROM')"
    echo "      -n|--native - Use the same base OS image as the running system"
    echo "      -p|--push - push the generated images to the specified registry"
    echo "      -t|--tag - tag to add to prplmesh-builder and prplmesh-runner images"
}

push() {
    if ! docker push "$1" ; then
	echo "Pushing $1 to the registry failed. Make sure you are
	logged-in (see docker-login)"
    fi

}

main() {
    OPTS=`getopt -o 'hnvb:t:p:' --long verbose,help,native,base-image:,tag:,push: -n 'parse-options' -- "$@"`

    if [ $? != 0 ] ; then err "Failed parsing options." >&2 ; usage; exit 1 ; fi

    eval set -- "$OPTS"

    while true; do
        case "$1" in
            -v | --verbose)         VERBOSE=true; shift ;;
            -h | --help)            usage; exit 0; shift ;;
            -b | --base-image)      IMAGE="$2"; shift ; shift ;;
            -n | --native)          IMAGE=$(
                                        . /etc/os-release
                                        distro="$(echo $NAME | awk '{print tolower($0)}')"
                                        echo "$distro:$VERSION_ID"
                                    ); shift ;;
	    -p | --push)            PUSH_REG="$2"; shift ; shift ;;
            -t | --tag)             TAG=":$2"; shift ; shift ;;
            -- ) shift; break ;;
            * ) err "unsupported argument $1"; usage; exit 1 ;;
        esac
    done

    dbg IMAGE=$IMAGE
    dbg TAG=$TAG
    dbg topdir=$topdir

    info "Base docker image $IMAGE"
    info "Generating builder docker image (prplmesh-builder$TAG)"
    run docker image build \
        --build-arg image=$IMAGE \
        --tag prplmesh-builder$TAG \
        ${scriptdir}/builder

    info "Generating runner docker image (prplmesh-runner$TAG)"
    run docker image build \
        --build-arg image=$IMAGE \
        --tag prplmesh-runner$TAG \
        ${scriptdir}/runner

    if [ ! -z "$PUSH_REG" ] ; then
	if [ -z "$TAG" ] ; then
	    echo "Error: cannot push an untagged image."
	    exit 1
	fi
	docker image tag "prplmesh-builder$TAG" "${PUSH_REG}/prplmesh-builder${TAG}"
	docker image tag "prplmesh-runner$TAG" "${PUSH_REG}/prplmesh-runner${TAG}"
	push "${PUSH_REG}/prplmesh-builder${TAG}"
	push "${PUSH_REG}/prplmesh-runner${TAG}"
    fi

}

VERBOSE=false
NATIVE=false
IMAGE="ubuntu:18.04"
PUSH_REG=""
TAG=""

main "$@"
