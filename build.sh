echo "BUILDING ENCODING"
go test github.com/kelbyludwig/cryptopals/encoding -v
go install github.com/kelbyludwig/cryptopals/encoding

echo "BUILDING XOR"
go test github.com/kelbyludwig/cryptopals/xor -v
go install github.com/kelbyludwig/cryptopals/xor
