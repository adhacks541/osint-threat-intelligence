$(document).ready(function() {
    // --- Initialization ---
    
    // Initialize DataTables with custom styling options
    var findingsTable = $('#findingsTable').DataTable({
        "paging": true,
        "searching": false,
        "info": false,
        "order": [[ 1, "desc" ]],
        "columnDefs": [ 
            { "orderable": false, "targets": 0 }
        ],
        "language": {
            "emptyTable": "No findings collected yet. Start a scan above!"
        },
        "drawCallback": function() {
            // Re-apply animations to new rows
            $('.dataTables_paginate .page-link').addClass('btn-outline-glow');
        }
    });

    // --- Data Loading ---
    function loadFindings() {
        var keyword = $('#searchKeyword').val();
        var port = $('#portFilter').val();
        var startDate = $('#startDate').val();
        var endDate = $('#endDate').val();

        // Show loading state if needed (optional)
        
        $.get('/search', {
            keyword: keyword,
            port: port,
            start_date: startDate,
            end_date: endDate
        }, function(data) {
            var table = $('#findingsTable').DataTable();
            table.clear();
            
            data.forEach(function(item, index) {
                var details = item[10]; // Details are in the 11th column
                
                // Create badge for source
                var sourceClass = 'badge-custom';
                if (item[3] === 'Shodan') sourceClass += ' badge-shodan';
                else if (item[3] === 'Google Dorks') sourceClass += ' badge-google';
                else if (item[3] === 'WHOIS') sourceClass += ' badge-whois';
                else sourceClass += ' bg-darker';

                var sourceBadge = `<span class="${sourceClass}">${item[3]}</span>`;

                var rowNode = table.row.add([
                    `<input type="checkbox" class="finding-checkbox form-check-input" value="${item[0]}">`,
                    `<span class="text-muted small font-monospace">${item[6]}</span>`, // timestamp
                    `<span class="fw-bold">${item[1]}</span>`, // type
                    `<span class="font-monospace text-break">${item[2]}</span>`, // value
                    sourceBadge  // source
                ]).draw(false).node();
                
                // Add animation class with delay
                $(rowNode).addClass('animate-fade-in');
                $(rowNode).css('animation-delay', (index * 0.05) + 's');
                
                // Attach details data
                if (details) {
                    $(rowNode).data('details', details);
                    $(rowNode).addClass('cursor-pointer');
                }
            });
            
            $('#selectAll').prop('checked', false);
            $('#deleteSelected').prop('disabled', true);
        });
    }

    function initializeDateFilters() {
        $.get('/get_date_range', function(data) {
            if (data.min_date && data.max_date) {
                $('#startDate').val(data.min_date);
                $('#endDate').val(data.max_date);
            }
        }).always(function() {
            loadFindings();
        });
    }

    // --- Event Handlers ---

    // Sidebar Toggle
    $('#sidebar-toggle').on('click', function() {
        $('#sidebar').toggleClass('collapsed');
        $('.main-content').toggleClass('collapsed');
    });

    // Collection Form
    var progressInterval;
    $('#collectForm').on('submit', function(e) {
        e.preventDefault();
        var $submitButton = $(this).find('button[type="submit"]');
        var originalBtnText = $submitButton.html();
        
        $submitButton.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Scanning...');
        
        var $progressBar = $('#collect-progress-bar');
        var $progressContainer = $progressBar.parent();
        
        $progressBar.css('width', '0%').removeClass('bg-danger').addClass('bg-success');
        $progressContainer.slideDown();
        
        progressInterval = setInterval(() => {
            let currentWidth = parseFloat($progressBar.css('width')) / $progressBar.parent().width() * 100;
            if (currentWidth < 90) {
                $progressBar.css('width', (currentWidth + 5) + '%');
            }
        }, 500);

        $.post('/collect', $(this).serialize())
            .done((response) => {
                Swal.fire({
                    title: 'Scan Complete!',
                    text: `Found ${response.findings.length} items.`,
                    icon: 'success',
                    background: '#1e293b',
                    color: '#fff',
                    confirmButtonColor: '#3b82f6'
                }).then(() => {
                    loadFindings();
                });
            })
            .fail((xhr) => {
                var msg = xhr.responseJSON ? xhr.responseJSON.message : 'Unknown error';
                $progressBar.removeClass('bg-success').addClass('bg-danger');
                Swal.fire({
                    title: 'Scan Failed',
                    text: msg,
                    icon: 'error',
                    background: '#1e293b',
                    color: '#fff'
                });
            })
            .always(() => {
                clearInterval(progressInterval);
                $progressBar.css('width', '100%');
                setTimeout(() => {
                    $progressContainer.slideUp();
                    $submitButton.prop('disabled', false).html(originalBtnText);
                }, 1000);
            });
    });

    // Findings Table Row Click for Details
    $('#findingsTable tbody').on('click', 'tr', function(event) {
        if ($(event.target).is('input:checkbox') || $(event.target).is('.finding-checkbox')) {
            return;
        }
        var detailsData = $(this).data('details');
        if (detailsData) {
            var formattedOutput;
            try {
                formattedOutput = JSON.stringify(JSON.parse(detailsData), null, 2);
            } catch (e) {
                formattedOutput = detailsData;
            }
            $('#detailsContent').text(formattedOutput);
            var detailsModal = new bootstrap.Modal(document.getElementById('detailsModal'));
            detailsModal.show();
        }
    });
    
    // Checkbox Logic
    $('#selectAll').on('click', function() {
        var rows = findingsTable.rows({ 'search': 'applied' }).nodes();
        $('input[type="checkbox"]', rows).prop('checked', this.checked);
        updateDeleteButtonState();
    });
    
    $('#findingsTable tbody').on('change', 'input[type="checkbox"]', function() {
        updateDeleteButtonState();
    });
    
    function updateDeleteButtonState() {
        var count = $('.finding-checkbox:checked').length;
        $('#deleteSelected').prop('disabled', count === 0);
        $('#deleteSelected span').text(count > 0 ? ` (${count})` : '');
    }
    
    $('#deleteSelected').on('click', function() {
        var selectedIds = $('.finding-checkbox:checked').map(function() { return $(this).val(); }).get();
        if (selectedIds.length === 0) return;
        
        Swal.fire({
            title: 'Delete Findings?', 
            text: `You are about to delete ${selectedIds.length} items. This cannot be undone.`,
            icon: 'warning', 
            showCancelButton: true, 
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#64748b',
            confirmButtonText: 'Delete',
            background: '#1e293b',
            color: '#fff'
        }).then((result) => {
            if (result.isConfirmed) {
                $.ajax({
                    url: '/delete_findings', type: 'POST', contentType: 'application/json',
                    data: JSON.stringify({ ids: selectedIds }),
                    success: (response) => { 
                        Swal.fire({
                            title: 'Deleted!', 
                            text: response.message, 
                            icon: 'success',
                            background: '#1e293b',
                            color: '#fff'
                        }); 
                        loadFindings(); 
                    },
                    error: () => Swal.fire('Error!', 'Failed to delete findings.', 'error')
                });
            }
        });
    });

    // Filters
    $('#searchKeyword, #portFilter, #startDate, #endDate').on('input change', function() {
        // Debounce slightly for text inputs
        clearTimeout(window.searchTimeout);
        window.searchTimeout = setTimeout(() => {
            loadFindings();
            if ($('#heatmap-tab').hasClass('active')) {
                $('#loadHeatmap').trigger('click');
            }
        }, 300);
    });

    // Heatmap & Report
    $('#loadHeatmap').on('click', function() {
        var url = `/heatmap?v=${new Date().getTime()}&port=${encodeURIComponent($('#portFilter').val())}&start_date=${encodeURIComponent($('#startDate').val())}&end_date=${encodeURIComponent($('#endDate').val())}`;
        $('#heatmapFrame').attr('src', url);
    });
    
    $('#exportPdfButton').on('click', function() {
        var $button = $(this);
        var originalText = $button.html();
        $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Generating...');
        
        $.ajax({
            url: '/export_pdf', method: 'GET', xhrFields: { responseType: 'blob' },
            success: function (blob) {
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'report.pdf';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                Swal.fire({
                    title: 'Downloaded!',
                    text: 'Report generated successfully.',
                    icon: 'success',
                    background: '#1e293b',
                    color: '#fff'
                });
            },
            error: () => Swal.fire({
                title: 'Error',
                text: 'Failed to generate report.',
                icon: 'error',
                background: '#1e293b',
                color: '#fff'
            }),
            complete: () => { $button.prop('disabled', false).html(originalText); }
        });
    });

    // Initialize
    initializeDateFilters();
});
