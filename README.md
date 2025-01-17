# abstratium-vault

A simple vault that restricts access to data by IP address
Cloud friendly, can for example be deployed with Google Cloud Run at very low cost, virtually free.

# Build and test locally with hotdeployment

Install `air`.

Install air for hot reload (https://github.com/air-verse/air):

    go install github.com/air-verse/air@latest

Install gotest for testing with colours (https://github.com/rakyll/gotest):

    go install github.com/rakyll/gotest
    sudo ln -s ~/go/bin/gotest /usr/local/bin/gotest

Build and run with hotdeploy:

    ./run.sh

Run unit tests as well as against the running server:

    ./test.sh

# Build for Google Cloud Run

Get Pack: https://buildpacks.io/docs/for-platform-operators/how-to/integrate-ci/pack/

    sudo add-apt-repository ppa:cncf-buildpacks/pack-cli
    sudo apt-get update
    sudo apt-get install pack-cli

Samples can be found here: https://github.com/GoogleCloudPlatform/buildpack-samples

Local pack:

    pack build --builder=gcr.io/buildpacks/builder abstratium-vault

Run the docker image:

    docker run -it --rm -p8080:8080 abstratium-vault

## Issues deploying to Google Cloud Run

    pack inspect-image abstratium-vault

    Processes:
    TYPE                 SHELL        COMMAND                                 ARGS        WORK DIR
    web (default)                     /layers/google.go.build/bin/main                    /workspace

Copy the command `/layers/google.go.build/bin/main` and paste it into the Google Cloud Run container settings in the field called "Container Command".

# Other stuff

## Git file permissions

add the file using git, so that it can be executed when it is checked out later:

    git update-index --chmod=+x run.sh test.sh

test that:

    git ls-files --stage

    100644 adc93f37d315f89b2dd77b2a14ff3524d24ea119 0	README.md
    100755 76d307f4e324837d2020527a49ab36ab334ee60a 0	run.sh
    100755 94aa1054ac0015a804fe6a6aac86e7bfc6e61096 0	test.sh

`755` is runable by everyone, `644` is read only for everyone.

