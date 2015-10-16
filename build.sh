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
echo "----------------------------------------------"
echo "BUILDING USER"
go test github.com/kelbyludwig/cryptopals/user -v
go install github.com/kelbyludwig/cryptopals/user
echo "----------------------------------------------"
echo "BUILDING AES"
go test github.com/kelbyludwig/cryptopals/aes -v
go install github.com/kelbyludwig/cryptopals/aes 
echo "----------------------------------------------"
echo "BUILDING MTRAND"
go test github.com/kelbyludwig/cryptopals/mtrand -v
go install github.com/kelbyludwig/cryptopals/mtrand
