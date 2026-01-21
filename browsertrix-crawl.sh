# This is a script that loops through a set of ETD submissions' extracted URLs files
# and runs a browsertrix-crawl for each.

# Pass argument of list of .urls files via commandline, such as
# 2023-December/*/*.pdf.urls
for datafile in "$@"; do
    # Get absolute path of seed file.
    datafile=$(realpath "$datafile")
    # Get just the seed file name.
    filename=$(basename "$datafile")
    # Get the submission part of the path.
    submission=$(echo "$datafile" | awk -F/ '{print $(NF-1)}')
    # Get name of the PDF the URLs came from.
    pdfname="${filename%.*}"
    # Get the PDF name without an extension.
    rootname="${pdfname%.*}"
    # Set a name for the collection used by Browsertrix Crawler.
    collectionname="${submission}_${rootname}"
    # Replace any spaces with underscore.
    collectionname="${collectionname// /_}"
    echo "Processing $filename to $collectionname"
    docker run -v "$datafile":/app/seedFile.txt -v $PWD/crawls:/crawls/ webrecorder/browsertrix-crawler crawl --seedFile /app/seedFile.txt --generateWACZ --scopeType page --generateCDX --screenshot thumbnail,fullPage --screencastPort 8061 -diskUtilization 95 --description "Data served from URLs parsed from ETD $pdfname" --warcinfo.operator "University of North Texas Libraries" --collection "$collectionname" --delay 6 --warcPrefix "UNT" --workers=2
    cp "$datafile" "$PWD/crawls/collections/$collectionname/"
done
