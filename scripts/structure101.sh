mkdir -p s101/repository/project
docker run --rm -e LABEL=baseline -v "${PWD}/s101":/etc/structure101 -v "${PWD}":/project jzheaux/structure101-build
