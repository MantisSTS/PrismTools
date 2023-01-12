# Check if Go is installed
go=$(command -v go)


if [ -z "$go" ]
then
    echo "Go could not be found"
    exit
fi

# Install Nuclei
$go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Find the path to the nuclei binary
nuclei=$(command -v nuclei)

if [ -z "$nuclei" ]
then
    echo "Nuclei could not be installed"
    exit
fi

# Install nuclei templates
$nuclei -update-templates

mkdir -p ./output/nuclei
mkdir -p ./output/custom

# Read in the file containing the list of URLs as a flag
while getopts f: flag
do
    case "${flag}" in
        f) file=${OPTARG};;
    esac
done

# Check if the -h flag was used
if [ -z "$file" ]
then
    echo "Usage: ./run.sh -f <file>"
    exit
fi

# Check if the file exists
if [ ! -f "$file" ]
then
    echo "File does not exist"
    exit
fi

# Read in the file containing the list of URLs
cat $file | $nuclei -t ~/nuclei-templates/ -o output/nuclei/nuclei_output_$(date +'%F').json -json

$go run main.go 