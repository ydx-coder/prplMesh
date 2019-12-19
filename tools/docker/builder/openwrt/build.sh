#!/bin/sh -e

scriptdir="$(cd "${0%/*}"; pwd)"
rootdir="${scriptdir%/*/*/*/*}"

. "${rootdir}/tools/docker/functions.sh"

usage() {
    echo "usage: $(basename $0) [-ipt]"
    echo "  options:"
    echo "      -h|--help - show this help menu"
    echo "      -d|--target-device the device to build for"
    echo "      -i|--image - build the docker image only"
    echo "      -o|--openwrt-version - the openwrt version to use"
    echo "      -r|--openwrt-repository - the openwrt repository to use"
    echo "      -t|--tag - the tag to use for the builder image"
    echo "      -v|--verbose - verbosity on"
    echo " -d is always required."
}

build_image() {
    # We first need to build the corresponding images
    docker build --tag "$image_tag" \
           --build-arg OPENWRT_REPOSITORY \
           --build-arg OPENWRT_VERSION \
           --build-arg TARGET \
           --build-arg PRPL_FEED \
           "$scriptdir/"
}

build_prplmesh() {
    dbg "Container name will be $container_name"
    container_name="prplmesh-builder-$(date +%F_%H-%M-%S)"
    docker run -i \
           --name "$container_name" \
           -e TARGET \
           -e OPENWRT_VERSION \
           -e PRPLMESH_VERSION \
           -v "$scriptdir/scripts:/home/openwrt/openwrt_sdk/build_scripts/:ro" \
           -v "${rootdir}:/home/openwrt/prplMesh_source:ro" \
           "$image_tag" \
           ./build_scripts/build.sh

    docker cp "${container_name}:/home/openwrt/openwrt_sdk/prplmesh-${TARGET}-${OPENWRT_VERSION}-${PRPLMESH_VERSION}.ipk" .

    docker rm "${container_name}"
}

main() {
    OPTS=`getopt -o 'hd:io:r:t:v' --long help,device:,image,openwrt-version:,openwrt-repository:,tag:,verbose -n 'parse-options' -- "$@"`

    if [ $? != 0 ] ; then err "Failed parsing options." >&2 ; usage; exit 1 ; fi

    eval set -- "$OPTS"

    while true; do
        case "$1" in
            -h | --help)               usage; exit 0; shift ;;
            -d | --target-device)      TARGET_DEVICE="$2"; shift ; shift ;;
            -i | --image)              IMAGE_ONLY=true; shift ;;
            -o | --openwrt-version)    OPENWRT_VERSION="$2"; shift; shift ;;
            -r | --openwrt-repository) OPENWRT_REPOSITORY="$2"; shift; shift ;;
            -t | --tag)                TAG="$2"; shift ; shift ;;
            -v | --verbose)            VERBOSE=true; shift ;;
            -- ) shift; break ;;
            * ) err "unsupported argument $1"; usage; exit 1 ;;
        esac
    done

    case "$TARGET_DEVICE" in
        turris-omnia)
            TARGET=mvebu
            ;;
        *)
            err "Unknown target device: $TARGET_DEVICE"
            info "Currently supported targets are: turris-omnia"
            ;;
    esac

    if [ -z "$OPENWRT_REPOSITORY" ] ; then
        OPENWRT_REPOSITORY=https://git.prpl.dev/prplmesh/prplwrt.git
        dbg "OPENWRT_REPOSITORY not set, using default value $OPENWRT_REPOSITORY"
    fi

    if [ -z "$OPENWRT_VERSION" ] ; then
        OPENWRT_VERSION=9d2efd
        dbg "OPENWRT_VERSION not set, using default value $OPENWRT_VERSION"
    fi

    if [ -z "$PRPL_FEED" ] ; then
        PRPL_FEED='https://git.prpl.dev/prplmesh/iwlwav.git^06a0126d5fb53b1d65bad90757a5f9f5f77419ca'
        dbg "PRPL_FEED not set, using default value $PRPL_FEED"
    fi

    if [ -n "$TAG" ] ; then
        image_tag=$TAG
    else
        image_tag="prplmesh-builder-${TARGET}:${OPENWRT_VERSION}"
        dbg "image tag not set, using default value $image_tag"
    fi

    export OPENWRT_REPOSITORY
    export OPENWRT_VERSION
    export TARGET
    PRPLMESH_VERSION="$(git describe --always --dirty --exclude '*')"
    export PRPLMESH_VERSION
    export PRPL_FEED

    if [ $IMAGE_ONLY = true ] ; then
        build_image
	exit $?
    fi

    build_image
    build_prplmesh

}

IMAGE_ONLY=false
VERBOSE=false

main "$@"
