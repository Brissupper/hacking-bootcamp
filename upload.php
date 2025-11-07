<?php
if(isset($_FILES['file'])){
    $file = $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/html/uploads/" . $file);
    echo "Uploaded: " . $file;
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit">
</form>
