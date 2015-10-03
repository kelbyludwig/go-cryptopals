echo "BUILDING ENCODING"
go test github.com/kelbyludwig/cryptopals/encoding -v
go install github.com/kelbyludwig/cryptopals/encoding
echo "----------------------------------------------"
echo "BUILDING XOR"
go test github.com/kelbyludwig/cryptopals/xor -v
go install github.com/kelbyludwig/cryptopals/xor
echo "----------------------------------------------"
echo "BUILDING CRYPTANALYSIS"
go test github.com/kelbyludwig/cryptopals/cryptanalysis -v
go install github.com/kelbyludwig/cryptopals/cryptanalysis

